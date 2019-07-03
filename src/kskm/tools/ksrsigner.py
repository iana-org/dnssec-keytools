#!/usr/bin/env python3
"""
KSR signer tool.

Process a KSR received from the ZSK operator and produce an SKR response
with signatures created using the KSK keys.
"""
import argparse
import logging.handlers
import os
import sys
from argparse import Namespace as ArgsType
from typing import Optional

import kskm.common
import kskm.ksr
import kskm.misc
import kskm.skr
from kskm.common.config import KSKMConfig
from kskm.common.config import get_config
from kskm.common.display import format_bundles_for_humans
from kskm.common.logging import get_logger
from kskm.signer import create_skr, output_skr_xml
from kskm.signer.policy import check_skr_and_ksr, check_last_skr_and_new_skr

__author__ = 'ft'

_DEFAULTS = {'debug': False,
             'syslog': False,
             'previous_skr': None,
             'config': None,
             'ksr': None,
             'skr': None,
             'schema': 'normal'
             }


def parse_args(defaults: dict) -> ArgsType:
    """
    Parse command line arguments.

    The KSR signer is mostly configured using the config file (--config), but
    some things such as output verbosity is settable using command line arguments.

    TODO: Further, it might be convenient to be able to override certain paths in the config
          file from the commandline - or?
    """
    parser = argparse.ArgumentParser(description='KSK request signer',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     )

    # Positional arguments
    parser.add_argument('ksr',
                        metavar='KSRFILE', type=str,
                        default=defaults['ksr'], nargs='?',
                        help='KSR request to process',
                        )

    parser.add_argument('skr',
                        metavar='SKRFILE', type=str,
                        default=defaults['skr'], nargs='?',
                        help='SKR output filename',
                        )
    # Optional arguments
    parser.add_argument('--schema',
                        dest='schema',
                        metavar='NAME', type=str,
                        default=defaults['schema'],
                        help='Name of schema (defined in config) to follow',
                        )
    parser.add_argument('--previous_skr',
                        dest='previous_skr',
                        metavar='SKRFILE', type=str,
                        default=defaults['previous_skr'],
                        help='Path to the previous SKR to use for validation',
                        )
    parser.add_argument('--config',
                        dest='config',
                        metavar='CFGFILE', type=str,
                        default=defaults['config'],
                        help='Path to the KSR signer configuration file',
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=defaults['debug'],
                        help='Enable debug operation',
                        )
    parser.add_argument('--syslog',
                        dest='syslog',
                        action='store_true', default=defaults['syslog'],
                        help='Enable syslog output',
                        )
    parser.add_argument('--force',
                        dest='force',
                        action='store_true',
                        default=False,
                        help='Don\'t ask for confirmation',
                        )
    args = parser.parse_args()
    return args


def _previous_skr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.previous_skr:
        return str(args.previous_skr)
    return config.get_filename('previous_skr')


def _ksr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.ksr:
        return str(args.ksr)
    return config.get_filename('input_ksr')


def _skr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.skr:
        return str(args.skr)
    return config.get_filename('output_skr')


def ksrsigner(logger: logging.Logger, args: ArgsType, config: Optional[KSKMConfig] = None) -> bool:
    """Parse KSR and previous SKR. Produce a new SKR."""
    #
    # Load configuration, if not provided already
    #
    if config is None:
        config = get_config(args.config)

    #
    # Load the previous SKR
    #
    skr = None
    _previous_skr = _previous_skr_filename(args, config)
    if _previous_skr:
        skr = kskm.skr.load_skr(_previous_skr, config.response_policy)
        logger.info('Previous SKR:')
        for x in format_bundles_for_humans(skr.bundles):
            logger.info(x)

    #
    # Load the KSR request
    #
    _ksr_fn = _ksr_filename(args, config)
    if _ksr_fn is None:
        logger.error("No KSR filename specified")
        return False
    request = kskm.ksr.load_ksr(_ksr_fn, config.request_policy)
    logger.info('Request:')
    for x in format_bundles_for_humans(request.bundles):
        logger.info(x)

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    p11modules = kskm.misc.hsm.init_pkcs11_modules_from_dict(config.hsm)

    #
    # Perform some checks that need both KSR, SKR and PKCS#11 modules
    #
    if skr is not None:
        check_skr_and_ksr(request, skr, config.request_policy)
        # TODO: Verify that the public key that signed the bundles in skr is available in the HSM
    else:
        logger.info('KSR-CHAIN-PRE/KSR-CHAIN-POST: Previous SKR *NOT* loaded - daisy chain not validated')
        logger.info('KSR-PREVIOUS: Previous SKR *NOT* loaded - presence of SKR(n-1) in HSM not validated')

    if not args.force:
        ack = input(f'Sign KSR? Confirm with "Yes" (exactly) or anything else to abort: ')
        if ack.strip('\n') != 'Yes':
            logger.info(f'KSR signing aborted')
            return False

    #
    # Create a new SKR
    #
    schema = config.get_schema(args.schema)
    new_skr = create_skr(request, schema, p11modules, config)
    if skr:
        check_last_skr_and_new_skr(skr, new_skr, config.request_policy)

    logger.info('Generated SKR:')
    for x in format_bundles_for_humans(new_skr.bundles):
        logger.info(x)

    _skr_fn = _skr_filename(args, config)
    output_skr_xml(new_skr, _skr_fn)

    return True


def main() -> None:
    """Main program function."""
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_DEFAULTS)
        logger = get_logger(progname, debug=args.debug, syslog=args.syslog, filelog=True)
        res = ksrsigner(logger, args)
        if res is True:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
