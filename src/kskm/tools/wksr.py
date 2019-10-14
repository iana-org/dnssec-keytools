#!/usr/bin/env python3

"""KSR Receiver Web Server."""

import argparse
import logging

import yaml

from kskm.wksr.server import (PeerCertWSGIRequestHandler, generate_app,
                              generate_ssl_context)

DEFAULT_PORT = 8443
DEFAULT_CONFIG = 'wksr.yaml'
DEFAULT_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-SHA384'
]


def main() -> None:
    """Main program function."""
    parser = argparse.ArgumentParser(description='KSR Web Server')

    parser.add_argument('--config',
                        dest='config',
                        metavar='filename',
                        default=DEFAULT_CONFIG,
                        help='Configuration file')
    parser.add_argument('--port',
                        dest='port',
                        default=DEFAULT_PORT,
                        help=f'Port to listen on (default {DEFAULT_PORT})')
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    config = yaml.load(open(args.config).read(), Loader=yaml.SafeLoader)

    ssl_context = generate_ssl_context(config['tls'])
    app = generate_app(config)

    app.run(port=args.port, ssl_context=ssl_context, request_handler=PeerCertWSGIRequestHandler)


if __name__ == "__main__":
    main()
