#!/usr/bin/env python3

"""KSR Receiver Web Server."""

import hashlib
import io
import logging
import re
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, Set, Tuple

import jinja2

from flask import Flask, render_template, request
from kskm.common.config import get_config
from kskm.common.validate import PolicyViolation
from kskm.ksr import load_ksr
from kskm.skr import load_skr
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import BadRequest, Forbidden, RequestEntityTooLarge

from .peercert import PeerCertWSGIRequestHandler

DEFAULT_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-SHA384'
]
DEFAULT_CONTENT_TYPE = 'application/xml'
DEFAULT_TEMPLATES_CONFIG = {
    'upload': 'upload.html',
    'result': 'result.html',
    'email': 'email.txt'
}
DEFAULT_MAX_SIZE = 1024 * 1024

client_whitelist: Set[str] = set()
ksr_config = None
notify_config: Dict[str, str] = {}
template_config: Dict[str, str] = {}


logger = logging.getLogger(__name__)


def authz() -> None:
    """Check TLS client whitelist."""
    digest = PeerCertWSGIRequestHandler.client_digest()
    if digest is None:
        logger.warning("Allowed client=%s digest=%s", request.remote_addr, digest)
        return
    if digest not in client_whitelist:
        logger.warning("Denied client=%s digest=%s", request.remote_addr, digest)
        raise Forbidden
    logger.info("Allowed client=%s digest=%s", request.remote_addr, digest)


def index() -> str:
    """Present homepage."""
    if 'peercert' in request.environ:
        subject = str(request.environ['peercert'].get_subject().commonName)
        return f"Hello world: {subject}"
    return f"Hello world: ANONYMOUS"


def upload() -> str:
    """Handle manual file upload."""
    if request.method == 'GET':
        return str(render_template(template_config['upload'], action=request.base_url))

    if 'ksr' not in request.files:
        raise BadRequest

    file = request.files['ksr']
    if file is None:
        raise BadRequest

    (filename, filehash) = save_ksr(file)

    # setup log capture
    log_capture_string = io.StringIO()
    ch = logging.StreamHandler(log_capture_string)
    ch.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(ch)

    result = validate_ksr(filename)

    # save captured log
    logging.getLogger().removeHandler(ch)
    log_buffer = log_capture_string.getvalue()
    log_capture_string.close()

    env = {
        'result': result,
        'request': request,
        'filename': filename,
        'filehash': filehash,
        'timestamp': datetime.utcnow(),
        'log': log_buffer
    }

    notify(env)

    return str(render_template(template_config['result'], **env))


def validate_ksr(filename: str) -> dict:
    """Validate incoming KSR and optionally check previous SKR."""
    global ksr_config

    if ksr_config:
        ksr_config_filename = ksr_config.get('ksrsigner_configfile')
        logger.info("Using ksrsigner configuration %s", ksr_config_filename)
    else:
        logger.warning("Using default ksrsigner configuration")
        ksr_config_filename = None

    # If ksr_config_filename is None, get_config returns a default policy
    config = get_config(ksr_config_filename)
    logger.debug("ksrsigner configuration loaded")

    result = {}
    previous_skr_filename = config.get_filename('previous_skr')

    try:
        if previous_skr_filename is not None:
            last_skr = load_skr(previous_skr_filename, config.response_policy)
            logger.info("Previous SKR loaded: %s", previous_skr_filename)
        else:
            last_skr = None

        ksr = load_ksr(filename, config.request_policy, raise_original=True)

        if last_skr is not None:
            check_skr_and_ksr(ksr, last_skr, config.request_policy)
            logger.info("Previous SKR checked: %s", previous_skr_filename)
        else:
            logger.warning("Previous SKR not checked")

        result['status'] = 'OK'
        result['message'] = f'KSR with id {ksr.id} loaded successfully'
    except PolicyViolation as exc:
        result['status'] = 'ERROR'
        result['message'] = str(exc)

    return result


def notify(env: dict) -> None:
    """Send notification about incoming KSR."""
    if 'smtp_server' not in notify_config:
        return
    msg = EmailMessage()
    body = render_template(template_config['email'], **env)
    msg.set_content(body)
    msg['Subject'] = notify_config['subject']
    msg['From'] = notify_config['from']
    msg['To'] = notify_config['to']
    smtp = smtplib.SMTP(notify_config['smtp_server'])
    smtp.send_message(msg)
    smtp.quit()


def save_ksr(upload_file: FileStorage) -> Tuple[str, str]:
    """Process incoming KSR."""
    if ksr_config is None:
        raise RuntimeError('Missing configuration')
    # check content type
    if upload_file.content_type != ksr_config.get('content_type', DEFAULT_CONTENT_TYPE):
        raise BadRequest

    # calculate file size
    filesize = len(upload_file.stream.read())
    if filesize > ksr_config.get('max_size', DEFAULT_MAX_SIZE):
        raise RequestEntityTooLarge
    upload_file.stream.seek(0)

    # calculate file checksum
    m = hashlib.new('sha256')
    m.update(upload_file.stream.read())
    upload_file.stream.seek(0)
    filehash = m.hexdigest()

    filename_prefix = ksr_config.get('prefix', 'upload_')
    filename_washed = re.sub(r'[^a-zA-Z0-9_]+', '_', str(upload_file.filename))
    filename_suffix = datetime.utcnow().strftime("_%Y%m%d_%H%M%S_%f")

    filename = filename_prefix + filename_washed + filename_suffix + ".xml"

    with open(filename, 'wb') as ksr_file:
        ksr_file.write(upload_file.stream.read())

    logger.info("Saved filename=%s size=%d hash=%s", filename, filesize, filehash)

    return filename, filehash


def generate_ssl_context(config: dict = {}) -> ssl.SSLContext:
    """Generate SSL context for app."""

    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=config.get('ca_cert'))
    ssl_context.options |= ssl.OP_NO_TLSv1
    ssl_context.options |= ssl.OP_NO_TLSv1_1

    if 'ciphers' in config:
        if isinstance(config['ciphers'], list):
            ciphers = ':'.join(config['ciphers'])
        else:
            ciphers = config['ciphers']
    else:
        ciphers = ':'.join(DEFAULT_CIPHERS)
    ssl_context.set_ciphers(ciphers)

    if config.get('require_client_cert', True):
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    else:
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
    ssl_context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])

    return ssl_context


def generate_app(config: dict) -> Flask:
    """Generate app."""
    global ksr_config, notify_config, template_config

    tls_config = config['tls']
    ksr_config = config.get('ksr', {})
    notify_config = config.get('notify', {})
    template_config = config.get('templates', DEFAULT_TEMPLATES_CONFIG)

    for client in tls_config.get('client_whitelist', []):
        client_whitelist.add(client)
        logger.info("Accepting TLS client SHA-256 fingerprint: %s", client)

    app = Flask(__name__)

    app.jinja_loader = jinja2.FileSystemLoader(".")  # type: ignore
    app.jinja_env.globals['client_subject'] = PeerCertWSGIRequestHandler.client_subject
    app.jinja_env.globals['client_digest'] = PeerCertWSGIRequestHandler.client_digest

    app.before_request(authz)

    app.add_url_rule('/', view_func=index, methods=['GET'])
    app.add_url_rule('/upload', view_func=upload, methods=['GET', 'POST'])

    return app
