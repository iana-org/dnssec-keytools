"""KSR Receiver Web Server."""

import hashlib
import io
import logging
import re
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import jinja2
from fastapi import APIRouter, FastAPI, HTTPException, Request, UploadFile, status
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from kskm.common.config import get_config
from kskm.common.config_wksr import WKSR_Config
from kskm.common.validate import PolicyViolation
from kskm.ksr import load_ksr
from kskm.signer.policy import check_skr_and_ksr
from kskm.skr import load_skr
from kskm.skr.data import Response
from kskm.wksr.peercert import (
    request_peercert_client_subject,
    request_peercert_digest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class ClientCertificateWhitelist(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: callable):
        """Check TLS client whitelist."""
        digest = request_peercert_digest(request)
        if digest is None:
            logger.warning(f"Allowed client={request.remote_addr} digest={digest}")
            return
        if digest not in request.app.config.tls.client_whitelist:
            logger.warning(f"Denied client={request.client.host} digest={digest}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        logger.info(f"Allowed client={request.client.host} digest={digest}")

        return await call_next(request)


@router.get("/")
async def index(request: Request) -> str:
    """Present homepage."""

    if client_name := request_peercert_client_subject(request):
        return f"Hello world: {client_name}"
    else:
        return "Hello world: ANONYMOUS"


@router.get("/upload")
async def upload_get(request: Request) -> str:
    """Handle manual file upload."""
    return request.app.templates.TemplateResponse(
        request=request,
        name=str(request.app.config.templates.upload),
        context={
            "action": str(request.base_url),
        },
    )


@router.post("/upload")
async def upload_post(request: Request, ksr: UploadFile) -> str:
    """Handle manual file upload."""

    (filename, filehash) = await save_ksr(request.app, ksr)

    # setup log capture
    log_capture_string = io.StringIO()
    log_handler = logging.StreamHandler(log_capture_string)
    log_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(log_handler)

    result = validate_ksr(request.app, filename)

    # save captured log
    logging.getLogger().removeHandler(log_handler)
    log_buffer = log_capture_string.getvalue()
    log_capture_string.close()

    env: dict[str, Any] = {
        "result": result,
        "remote_addr": request.client.host if request.client else None,
        "filename": filename,
        "filehash": filehash,
        "timestamp": datetime.now(UTC),
        "log": log_buffer,
        "client_subject": request_peercert_client_subject(request),
        "client_digest": request_peercert_digest(request),
    }

    notify(request.app, env)

    return request.app.templates.TemplateResponse(
        request=request, name=str(request.app.config.templates.result), context=env
    )


class WKSR(FastAPI):
    def __init__(
        self,
        config: WKSR_Config,
    ):
        super().__init__()

        self.config = config

        for client in self.config.tls.client_whitelist:
            logger.info(f"Accepting TLS client SHA-256 fingerprint: {client}")

        self.templates = Jinja2Templates(directory=".")

        self.include_router(router)
        self.add_middleware(ClientCertificateWhitelist)


def validate_ksr(app: WKSR, filename: Path) -> dict[str, str]:
    """Validate incoming KSR and optionally check previous SKR."""
    ksr_config_filename = None

    if app.config.ksr and app.config.ksr.ksrsigner_configfile:
        ksr_config_filename = app.config.ksr.ksrsigner_configfile
        logger.info(f"Using ksrsigner configuration {ksr_config_filename}")
    else:
        logger.warning("Using default ksrsigner configuration")
        ksr_config_filename = None

    # If ksr_config_filename is None, get_config returns a default policy
    config = get_config(ksr_config_filename)
    logger.debug("ksrsigner configuration loaded")

    result: dict[str, str] = {}
    previous_skr_filename = config.filenames.previous_skr
    previous_skr: Response | None

    try:
        if previous_skr_filename is not None:
            previous_skr = load_skr(previous_skr_filename, config.response_policy)
            logger.info("Previous SKR loaded: %s", previous_skr_filename)
        else:
            logger.warning("No previous SKR loaded")
            previous_skr = None

        ksr = load_ksr(filename, config.request_policy, raise_original=True)

        if previous_skr is not None:
            check_skr_and_ksr(ksr, previous_skr, config.request_policy, p11modules=None)
            logger.info("Previous SKR checked: %s", previous_skr_filename)
        else:
            logger.warning("Previous SKR not checked")

        result["status"] = "OK"
        result["message"] = f"KSR with id {ksr.id} loaded successfully"
    except PolicyViolation as exc:
        result["status"] = "ERROR"
        result["message"] = str(exc)

    return result


def notify(app: WKSR, env: dict[str, Any]) -> None:
    """Send notification about incoming KSR."""

    if not app.config.notify or not app.config.notify.smtp_server:
        return

    template: jinja2.Template = app.templates.get_template(
        str(app.config.templates.email)
    )
    body = template.render(**env)

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = app.config.notify.subject
    msg["From"] = app.config.notify.from_
    msg["To"] = app.config.notify.to
    smtp = smtplib.SMTP(app.config.notify.smtp_server)
    smtp.send_message(msg)
    smtp.quit()


async def save_ksr(app: WKSR, upload_file: UploadFile) -> tuple[Path, str]:
    """Process incoming KSR."""

    # check content type
    if upload_file.content_type != app.config.ksr.content_type:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if upload_file.size is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    # check file max size
    if upload_file.size > app.config.ksr.max_size:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    contents = await upload_file.read()

    # calculate file checksum
    digest = hashlib.new("sha256")
    digest.update(contents)
    filehash = digest.hexdigest()

    filename_washed = re.sub(r"[^a-zA-Z0-9_]+", "_", str(upload_file.filename))
    filename_suffix = datetime.now(UTC).strftime("_%Y%m%d_%H%M%S_%f")

    filename = Path(
        str(app.config.ksr.prefix) + filename_washed + filename_suffix + ".xml"
    )

    with open(filename, "wb") as ksr_file:
        ksr_file.write(contents)

    logger.info(
        "Saved filename=%s size=%d hash=%s", filename, upload_file.size, filehash
    )

    return filename, filehash
