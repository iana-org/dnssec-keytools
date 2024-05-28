"""KSR Receiver Web Server."""

import argparse
import logging
import ssl

import uvicorn
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

from kskm.version import __verbose_version__
from kskm.wksr.server import WKSR

DEFAULT_HOSTNAME = "127.0.0.1"
DEFAULT_PORT = 8443
DEFAULT_CONFIG = "wksr.yaml"


def patch_request_scope_transport():
    """
    Patch transport for FastAPI.Request.scope

    Required until the "ASGI TLS Extension" has been implemented
    https://asgi.readthedocs.io/en/latest/specs/tls.html
    """
    old_on_url = HttpToolsProtocol.on_url

    def new_on_url(self, url):
        old_on_url(self, url)
        self.scope["transport"] = self.transport

    HttpToolsProtocol.on_url = new_on_url


def main() -> None:
    """Main program function."""
    parser = argparse.ArgumentParser(
        description=f"KSR Web Server {__verbose_version__}",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--config",
        dest="config",
        metavar="filename",
        default=DEFAULT_CONFIG,
        help="Configuration file",
    )
    parser.add_argument(
        "--hostname",
        dest="hostname",
        default=DEFAULT_HOSTNAME,
        help=f"Default hostname (default {DEFAULT_HOSTNAME})",
    )
    parser.add_argument(
        "--port", dest="port", type=int, default=DEFAULT_PORT, help="Port to listen on"
    )
    parser.add_argument(
        "--debug", dest="debug", action="store_true", help="Enable debugging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        log_level = "debug"
    else:
        logging.basicConfig(level=logging.INFO)
        log_level = "info"

    patch_request_scope_transport()

    app = WKSR.from_file(args.config)

    ssl_cert_reqs = (
        ssl.CERT_REQUIRED if app.config.tls.require_client_cert else ssl.CERT_OPTIONAL
    )

    # start application using uvicorn
    uvicorn.run(
        app=app,
        host=args.hostname,
        port=args.port,
        log_level=log_level,
        ssl_ciphers=":".join(app.config.tls.ciphers),
        ssl_certfile=str(app.config.tls.cert),
        ssl_keyfile=str(app.config.tls.key),
        ssl_ca_certs=str(app.config.tls.ca_cert),
        ssl_cert_reqs=ssl_cert_reqs,
    )


if __name__ == "__main__":
    main()
