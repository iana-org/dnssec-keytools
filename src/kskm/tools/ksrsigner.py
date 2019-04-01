#!/usr/bin/env python3
"""
KSR signer tool.

Process a KSR received from the ZSK operator and produce an SKR response
with signatures created using the KSK keys.
"""
import os
import sys
import argparse
import logging.handlers

from typing import Optional
from argparse import Namespace as ArgsType

import kskm.ksr
import kskm.skr
import kskm.misc
import kskm.common
from kskm.signer import create_skr, output_skr_xml
from kskm.tools_common.display import format_bundles_for_humans
from kskm.tools_common.logging import get_logger
from kskm.tools_common.daisy import check_daisy_chain
from kskm.common.config import filename as config_filename, get_config, get_schema, ConfigType

__author__ = 'ft'

_DEFAULTS = {'debug': False,
             'syslog': False,
             'hsm_config_dir': '/opt/dnssec',
             'request_policy': None,
             'response_policy': None,
             'previous_skr': None,
             'config': None,
             'ksr': None,
             'skr': None,
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
    parser.add_argument('--hsm_config_dir',
                        dest='hsm_config_dir',
                        metavar='DIR', type=str,
                        default=defaults['hsm_config_dir'],
                        help='Path to HSM configuration files',
                        )
    parser.add_argument('--request_policy',
                        dest='request_policy',
                        metavar='POLICYFILE', type=str,
                        default=defaults['request_policy'],
                        help='Path to YAML file with request policy',
                        )
    parser.add_argument('--response_policy',
                        dest='response_policy',
                        metavar='POLICYFILE', type=str,
                        default=defaults['response_policy'],
                        help='Path to YAML file with response policy',
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
    args = parser.parse_args()
    return args


def _previous_skr_filename(args: Optional[ArgsType], config: ConfigType) -> Optional[str]:
    if args and args.previous_skr:
        return args.previous_skr
    return config_filename('previous_skr', config)


def _ksr_filename(args: Optional[ArgsType], config: ConfigType) -> Optional[str]:
    if args and args.ksr:
        return args.ksr
    return config_filename('current_ksr', config)


def _skr_filename(args: Optional[ArgsType], config: ConfigType) -> Optional[str]:
    if args and args.skr:
        return args.skr
    return config_filename('current_skr', config)


def main(logger: logging.Logger, args: Optional[ArgsType], config: Optional[ConfigType] = None) -> bool:
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
        response_policy = kskm.skr.get_response_policy(args.response_policy, config)
        skr = kskm.skr.load_skr(_previous_skr, response_policy)
        logger.info('Previous SKR:')
        [logger.info(x) for x in format_bundles_for_humans(skr.bundles)]

    #
    # Load the KSR request
    #
    request_policy = kskm.ksr.get_request_policy(args.request_policy, config)

    _ksr_fn = _ksr_filename(args, config)
    request = kskm.ksr.load_ksr(_ksr_fn, request_policy)
    logger.info('Request:')
    [logger.info(x) for x in format_bundles_for_humans(request.bundles)]

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    p11modules = kskm.misc.hsm.init_pkcs11_modules(args.hsm_config_dir)

    #
    # Perform some checks that need both KSR, SKR and PKCS#11 modules
    #
    if skr is not None:
        check_daisy_chain(request, skr, request_policy)
        # TODO: Verify that the public key that signed the bundles in skr is available in the HSM
    else:
        logger.info('KSR-CHAIN-PRE/KSR-CHAIN-POST: Previous SKR *NOT* loaded - daisy chain not validated')
        logger.info('KSR-PREVIOUS: Previous SKR *NOT* loaded - presence of SKR(n-1) in HSM not validated')

    #
    # Create a new SKR
    #
    schema = get_schema('normal', config)
    new_skr = create_skr(request, schema, p11modules, config)

    _skr_fn = _skr_filename(args, config)
    output_skr_xml(new_skr, _skr_fn)

    return True


if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_DEFAULTS)
        logger = get_logger(progname, debug=args.debug, syslog=args.syslog)
        res = main(logger, args)
        if res is True:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
