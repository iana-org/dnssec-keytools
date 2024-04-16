"""KSR Receiver Web Server."""

import argparse
import logging

import yaml
from werkzeug.serving import run_simple

from kskm.common.config_schema import WKSR_Templates, WKSRConfig
from kskm.version import __verbose_version__
from kskm.wksr.peercert import PeerCertWSGIRequestHandler
from kskm.wksr.server import (
    DEFAULT_TEMPLATES_CONFIG,
    generate_app,
    generate_ssl_context,
)

DEFAULT_HOSTNAME = "127.0.0.1"
DEFAULT_PORT = 8443
DEFAULT_CONFIG = "wksr.yaml"


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

    with open(args.config) as fp:
        _config = yaml.load(fp.read(), Loader=yaml.SafeLoader)

    # try:
    #     voluptuous.humanize.validate_with_humanized_errors(_config, WKSR_CONFIG_SCHEMA)
    # except voluptuous.error.Error as exc:
    #     logging.critical(str(exc))
    #     sys.exit(-1)

    config = WKSRConfig(**_config)
    if not config.templates:
        config.templates = WKSR_Templates.model_validate(DEFAULT_TEMPLATES_CONFIG)

    ssl_context = generate_ssl_context(config.tls)
    app = generate_app(config)

    run_simple(
        hostname=args.hostname,
        port=args.port,
        ssl_context=ssl_context,
        application=app,
        request_handler=PeerCertWSGIRequestHandler,
    )


if __name__ == "__main__":
    main()
