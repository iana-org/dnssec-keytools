#!/usr/bin/env python3

"""KSR Receiver Web Server."""

import argparse
import hashlib
import logging
import smtplib
import ssl
import uuid
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, Optional, Set, Tuple

import jinja2
import OpenSSL
import werkzeug.serving
import yaml
from flask import Flask, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import BadRequest, Forbidden, RequestEntityTooLarge

from kskm.common.config import get_config
from kskm.common.validate import PolicyViolation
from kskm.ksr import load_ksr

DEFAULT_CONFIG = 'wksr.yaml'
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

app = Flask(__name__)
# TODO: These can be moved onto the 'app' instance, and accessed using the Flask 'current_app' Application Context.
client_whitelist: Set[str] = set()
ksr_config = None
notify_config = None
template_config = None


@app.before_request
def authz() -> None:
    """Check TLS client whitelist."""
    digest = PeerCertWSGIRequestHandler.client_digest()
    # we allow no certificate for now
    # TODO: Disable no-cert mode.
    if digest is None:
        logging.warning("Allowed client=%s digest=%s", request.remote_addr, digest)
        return
    if digest not in client_whitelist:
        # TODO: use format strings consistently.
        #       Saving cycles on logging isn't justifiable in this code base. Consistency improves auditability.
        logging.warning("Denied client=%s digest=%s", request.remote_addr, digest)
        raise Forbidden
    logging.info("Allowed client=%s digest=%s", request.remote_addr, digest)


@app.route('/', methods=['GET'])
def index() -> str:
    """Present homepage."""
    if 'peercert' in request.environ:
        subject = str(request.environ['peercert'].get_subject().commonName)
        return f"Hello world: {subject}"
    return f"Hello world: ANONYMOUS"


@app.route('/upload', methods=['GET', 'POST'])
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
    result = validate_ksr(filename)

    env = {
        'result': result,
        'request': request,
        'filename': filename,
        'filehash': filehash,
        'timestamp': datetime.utcnow()
    }

    notify(env)

    return str(render_template(template_config['result'], **env))


def validate_ksr(filename: str) -> dict:
    """Validate incoming KSR."""
    global ksr_config
    config_fn = None
    if ksr_config:
        config_fn = ksr_config.get('ksrsigner_configfile')
    # If config_fn is None, get_request_policy returns a default policy
    _config = get_config(config_fn)
    result = {}
    try:
        ksr = load_ksr(filename, _config.request_policy, raise_original=True)
        result['status'] = 'OK'
        result['message'] = f'KSR with id {ksr.id} loaded successfully'
    except PolicyViolation as exc:
        result['status'] = 'ERROR'
        result['message'] = str(exc)
    return result


def notify(env: dict) -> None:
    """Send notification about incoming KSR."""
    if notify_config is None:
        return
    msg = EmailMessage()
    body = render_template(template_config['email'], **env)
    msg.set_content(body)
    msg['Subject'] = notify_config.get('subject')
    msg['From'] = notify_config.get('from')
    msg['To'] = notify_config.get('to')
    smtp = smtplib.SMTP(notify_config.get('smtp_server'))
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

    # save file
    # TODO: using a client supplied filename would of course add to the attack surface, and need sanitation,
    # but wouldn't the KSK operator want to preserve the name of the request from the ZSK operator?
    # Alternatively, maybe use ISO8601 datetime (with microseconds, or a counter) as filename,
    # to at least make them sortable.
    # TODO: use os.path.join
    filename = f"{ksr_config.get('prefix', '')}{str(uuid.uuid4())}.xml"
    with open(filename, 'wb') as ksr_file:
        ksr_file.write(upload_file.stream.read())

    logging.info("Saved filename=%s size=%d hash=%s", filename, filesize, filehash)

    # TODO: Borderline OCD in this case, but I've actually started returning instances of small dataclasses
    #       whenever I want to return multiple values.
    return filename, filehash


# TLS client auth based on post at https://www.ajg.id.au/2018/01/01/mutual-tls-with-python-flask-and-werkzeug/
class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """
    TLS Client Certificate Authenticator.

    We subclass this class so that we can gain access to the connection
    property. self.connection is the underlying client socket. When a TLS
    connection is established, the underlying socket is an instance of
    SSLSocket, which in turn exposes the getpeercert() method.

    The output from that method is what we want to make available elsewhere
    in the application.
    """

    def make_environ(self) -> dict:
        """
        Create request environment.

        The superclass method develops the environ hash that eventually
        forms part of the Flask request object.

        We allow the superclass method to run first, then we insert the
        peer certificate into the hash. That exposes it to us later in
        the request variable that Flask provides
        """
        environ: Dict = super().make_environ()
        try:
            x509_binary = self.connection.getpeercert(True)  # type: ignore
        except AttributeError:
            # Not a TLS connection
            x509_binary = None
        if x509_binary is not None:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
            environ['peercert'] = x509
        return environ

    @classmethod
    def client_subject(cls) -> Optional[str]:
        """Find TLS client certificate subject."""
        peercert = request.environ['peercert']
        if peercert is None:
            return None
        c = peercert.get_subject().get_components()
        return str(c)

    @classmethod
    def client_digest(cls) -> Optional[str]:
        """Find TLS client certficate digest."""
        peercert = request.environ['peercert']
        if peercert is None:
            return None
        return str(peercert.digest('sha256').decode().replace(':', '').lower())


def main() -> None:
    """Main program function."""
    global ksr_config, notify_config, template_config

    parser = argparse.ArgumentParser(description='KSR Web Server')

    parser.add_argument('--config',
                        dest='config',
                        metavar='filename',
                        default=DEFAULT_CONFIG,
                        help='Configuration file')
    parser.add_argument('--port',
                        dest='port',
                        default=8443,
                        help='Port to listen on')
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    config = yaml.load(open(args.config).read(), Loader=yaml.SafeLoader)
    tls_config = config['tls']
    ksr_config = config.get('ksr', {})
    notify_config = config.get('notify')
    template_config = config.get('notify', DEFAULT_TEMPLATES_CONFIG)

    for client in tls_config.get('client_whitelist', []):
        client_whitelist.add(client)
        logging.info("Accepting TLS client SHA-256 fingerprint: %s", client)

    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=tls_config['ca_cert'])
    ssl_context.options |= ssl.OP_NO_TLSv1
    ssl_context.options |= ssl.OP_NO_TLSv1_1

    if 'ciphers' in tls_config:
        if isinstance(tls_config['ciphers'], list):
            ciphers = ':'.join(tls_config['ciphers'])
        else:
            ciphers = tls_config['ciphers']
    else:
        ciphers = ':'.join(DEFAULT_CIPHERS)
    ssl_context.set_ciphers(ciphers)

    if tls_config.get('require_client_cert', True):
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    else:
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
    ssl_context.load_cert_chain(certfile=tls_config['cert'], keyfile=tls_config['key'])

    app.jinja_loader = jinja2.FileSystemLoader(".")  # type: ignore
    app.jinja_env.globals['client_subject'] = PeerCertWSGIRequestHandler.client_subject
    app.jinja_env.globals['client_digest'] = PeerCertWSGIRequestHandler.client_digest

    app.run(port=args.port, ssl_context=ssl_context, request_handler=PeerCertWSGIRequestHandler)


if __name__ == "__main__":
    main()
