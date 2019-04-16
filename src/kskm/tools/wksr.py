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
from typing import Optional, Tuple

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
DEFAULT_CIPHERS = 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384'

app = Flask(__name__)
client_whitelist = set()
ksr_config = None
notify_config = None


@app.before_request
def authz():
    """Check TLS client whitelist."""
    digest = PeerCertWSGIRequestHandler.client_digest()
    # we allow no certificate for now
    if digest is None:
        logging.warning("Allowed client=%s digest=%s", request.remote_addr, digest)
        return
    if digest not in client_whitelist:
        logging.warning("Denied client=%s digest=%s", request.remote_addr, digest)
        raise Forbidden
    logging.info("Allowed client=%s digest=%s", request.remote_addr, digest)


@app.route('/', methods=['GET'])
def index():
    """Present homepage."""
    if 'peercert' in request.environ:
        subject = str(request.environ['peercert'].get_subject().commonName)
        return f"Hello world: {subject}"
    else:
        return f"Hello world: ANONYMOUS"


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Handle manual file upload."""
    if request.method == 'GET':
        return render_template("upload.html", action=request.base_url)

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

    if notify_config is not None:
        notify(env)

    return render_template("result.html", **env)


def validate_ksr(filename: str) -> dict:
    """Validate incoming KSR."""
    global ksk_config
    config_fn = ksk_config.get('ksrsigner_configfile')
    # If config_fn is None, get_request_policy returns a default policy
    _config = get_config(config_fn)
    request_policy = _config.get_request_policy()
    result = {}
    try:
        ksr = load_ksr(filename, request_policy, raise_original=True)
        result['status'] = 'OK'
        result['message'] = f'KSR with id {ksr.id} loaded successfully'
    except PolicyViolation as exc:
        result['status'] = 'ERROR'
        result['message'] = str(exc)
    return result


def notify(env: dict) -> None:
    """Send notification about incoming KSR."""
    msg = EmailMessage()
    body = render_template("email.txt", **env)
    msg.set_content(body)
    msg['Subject'] = notify_config.get('subject')
    msg['From'] = notify_config.get('from')
    msg['To'] = notify_config.get('to')
    smtp = smtplib.SMTP(notify_config.get('smtp_server'))
    smtp.send_message(msg)
    smtp.quit()


def save_ksr(upload_file: FileStorage) -> Tuple[str, str]:
    """Process incoming KSR."""
    # check content type
    if upload_file.content_type != ksr_config.get('content_type'):
        raise BadRequest

    # calculate file size
    filesize = len(upload_file.stream.read())
    if filesize > ksr_config.get('max_size'):
        raise RequestEntityTooLarge
    upload_file.stream.seek(0)

    # calculate file checksum
    m = hashlib.new('sha256')
    m.update(upload_file.stream.read())
    upload_file.stream.seek(0)
    filehash = m.hexdigest()

    # save file
    filename = f"{ksr_config.get('prefix','')}{str(uuid.uuid4())}.xml"
    with open(filename, 'wb') as ksr_file:
        ksr_file.write(upload_file.stream.read())

    logging.info("Saved filename=%s size=%d hash=%s", filename, filesize, filehash)

    return (filename, filehash)


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

    def make_environ(self):
        """
        Create request environment.

        The superclass method develops the environ hash that eventually
        forms part of the Flask request object.

        We allow the superclass method to run first, then we insert the
        peer certificate into the hash. That exposes it to us later in
        the request variable that Flask provides
        """
        environ = super().make_environ()
        x509_binary = self.connection.getpeercert(True)
        if x509_binary is not None:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
            environ['peercert'] = x509
        return environ

    @classmethod
    def client_subject(cls) -> Optional[str]:
        """Find TLS client certificate subject."""
        peercert = request.environ['peercert']
        if peercert is None:
            return
        c = peercert.get_subject().get_components()
        return str(c)

    @classmethod
    def client_digest(cls) -> Optional[str]:
        """Find TLS client certficate digest."""
        peercert = request.environ['peercert']
        if peercert is None:
            return
        return peercert.digest('sha256').decode().replace(':', '').lower()


def main():
    """Main program function."""
    global ksr_config, notify_config

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

    for client in config.get('client_whitelist', []):
        client_whitelist.add(client)

    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=tls_config['ca_cert'])
    ssl_context.minimum_version = ssl.PROTOCOL_TLSv1_2
    ssl_context.set_ciphers(tls_config.get('ciphers', DEFAULT_CIPHERS))
    if tls_config.get('require_client_cert', True):
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    else:
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
    ssl_context.load_cert_chain(certfile=tls_config['cert'], keyfile=tls_config['key'])

    app.jinja_loader = jinja2.FileSystemLoader(".")
    app.jinja_env.globals['client_subject'] = PeerCertWSGIRequestHandler.client_subject
    app.jinja_env.globals['client_digest'] = PeerCertWSGIRequestHandler.client_digest

    app.run(port=args.port, ssl_context=ssl_context, request_handler=PeerCertWSGIRequestHandler)


if __name__ == "__main__":
    main()
