#!/usr/bin/env python3

"""KSR Receiver Web Server."""

import hashlib
import io
import logging
import re
import smtplib
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import jinja2
from flask import Flask, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import BadRequest, Forbidden, RequestEntityTooLarge

from kskm.common.config import get_config
from kskm.common.config_wksr import WKSR_TLS, WKSR_Config
from kskm.common.validate import PolicyViolation
from kskm.ksr import load_ksr
from kskm.signer.policy import check_skr_and_ksr
from kskm.skr import load_skr
from kskm.skr.data import Response

from .peercert import PeerCertWSGIRequestHandler

DEFAULT_TEMPLATES_CONFIG = {
    "upload": "upload.html",
    "result": "result.html",
    "email": "email.txt",
}

wksr_config: WKSR_Config | None = None


logger = logging.getLogger(__name__)


def authz() -> None:
    """Check TLS client whitelist."""
    if wksr_config is None:
        raise RuntimeError("Missing configuration")

    digest = PeerCertWSGIRequestHandler.client_digest()
    if digest is None:
        logger.warning(f"Allowed client={request.remote_addr} digest={digest}")
        return
    if digest not in wksr_config.tls.client_whitelist:
        logger.warning(f"Denied client={request.remote_addr} digest={digest}")
        raise Forbidden
    logger.info(f"Allowed client={request.remote_addr} digest={digest}")


def index() -> str:
    """Present homepage."""
    if "peercert" in request.environ:
        subject = str(request.environ["peercert"].get_subject().commonName)
        return f"Hello world: {subject}"
    return "Hello world: ANONYMOUS"


def upload() -> str:
    """Handle manual file upload."""
    if wksr_config is None:
        raise RuntimeError("Missing configuration")

    if request.method == "GET":
        return str(
            render_template(str(wksr_config.templates.upload), action=request.base_url)
        )

    if "ksr" not in request.files:
        raise BadRequest

    file = request.files["ksr"]
    if file is None:
        raise BadRequest

    (filename, filehash) = save_ksr(file)

    # setup log capture
    log_capture_string = io.StringIO()
    log_handler = logging.StreamHandler(log_capture_string)
    log_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(log_handler)

    result = validate_ksr(filename)

    # save captured log
    logging.getLogger().removeHandler(log_handler)
    log_buffer = log_capture_string.getvalue()
    log_capture_string.close()

    env: dict[str, Any] = {
        "result": result,
        "request": request,
        "filename": filename,
        "filehash": filehash,
        "timestamp": datetime.now(UTC),
        "log": log_buffer,
    }

    notify(env)

    return str(render_template(str(wksr_config.templates.result), **env))


def validate_ksr(filename: Path) -> dict[str, str]:
    """Validate incoming KSR and optionally check previous SKR."""
    ksr_config_filename = None

    if wksr_config and wksr_config.ksr and wksr_config.ksr.ksrsigner_configfile:
        ksr_config_filename = wksr_config.ksr.ksrsigner_configfile
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


def notify(env: dict[str, Any]) -> None:
    """Send notification about incoming KSR."""
    if wksr_config is None:
        raise RuntimeError("Missing configuration")
    if not wksr_config.notify or not wksr_config.notify.smtp_server:
        return
    msg = EmailMessage()
    body = render_template(str(wksr_config.templates.email), **env)
    msg.set_content(body)
    msg["Subject"] = wksr_config.notify.subject
    msg["From"] = wksr_config.notify.from_
    msg["To"] = wksr_config.notify.to
    smtp = smtplib.SMTP(wksr_config.notify.smtp_server)
    smtp.send_message(msg)
    smtp.quit()


def save_ksr(upload_file: FileStorage) -> tuple[Path, str]:
    """Process incoming KSR."""
    if wksr_config is None:
        raise RuntimeError("Missing configuration")
    # check content type
    if upload_file.content_type != wksr_config.ksr.content_type:
        raise BadRequest

    # calculate file size
    filesize = len(upload_file.stream.read())
    if filesize > wksr_config.ksr.max_size:
        raise RequestEntityTooLarge
    upload_file.stream.seek(0)

    # calculate file checksum
    digest = hashlib.new("sha256")
    digest.update(upload_file.stream.read())
    filehash = digest.hexdigest()
    upload_file.stream.seek(0)

    filename_washed = re.sub(r"[^a-zA-Z0-9_]+", "_", str(upload_file.filename))
    filename_suffix = datetime.now(UTC).strftime("_%Y%m%d_%H%M%S_%f")

    filename = wksr_config.ksr.prefix.joinpath(
        filename_washed + filename_suffix + ".xml"
    )

    with open(filename, "wb") as ksr_file:
        ksr_file.write(upload_file.stream.read())

    logger.info("Saved filename=%s size=%d hash=%s", filename, filesize, filehash)

    return filename, filehash


def generate_ssl_context(config: WKSR_TLS) -> ssl.SSLContext:
    """Generate SSL context for app."""
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH, cafile=config.ca_cert
    )
    ssl_context.options |= ssl.OP_NO_TLSv1
    ssl_context.options |= ssl.OP_NO_TLSv1_1

    ssl_context.set_ciphers(":".join(config.ciphers))

    if config.require_client_cert:
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    else:
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
    ssl_context.load_cert_chain(certfile=config.cert, keyfile=config.key)

    return ssl_context


def generate_app(config: WKSR_Config) -> Flask:
    """Generate app."""
    global wksr_config

    wksr_config = config

    for client in config.tls.client_whitelist:
        logger.info(f"Accepting TLS client SHA-256 fingerprint: {client}")

    app = Flask(__name__)

    app.jinja_loader = jinja2.FileSystemLoader(".")
    app.jinja_env.globals["client_subject"] = PeerCertWSGIRequestHandler.client_subject
    app.jinja_env.globals["client_digest"] = PeerCertWSGIRequestHandler.client_digest

    app.before_request(authz)

    app.add_url_rule("/", view_func=index, methods=["GET"])
    app.add_url_rule("/upload", view_func=upload, methods=["GET", "POST"])

    return app
