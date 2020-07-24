"""
KSR signer tool.

Process a KSR received from the ZSK operator and produce an SKR response
with signatures created using the KSK keys.
"""
import argparse
import binascii
import logging.handlers
import os
import sys
from argparse import Namespace as ArgsType
from typing import Optional

import kskm.common
import kskm.ksr
import kskm.misc
import kskm.skr
from kskm.common.config import ConfigurationError, KSKMConfig, get_config
from kskm.common.display import format_bundles_for_humans
from kskm.common.logging import get_logger
from kskm.common.wordlist import pgp_wordlist
from kskm.signer import create_skr, output_skr_xml
from kskm.signer.policy import check_last_skr_and_new_skr, check_skr_and_ksr
from kskm.version import __verbose_version__

__author__ = "ft"

_DEFAULTS = {
    "debug": False,
    "syslog": False,
    "previous_skr": None,
    "config": "ksrsigner.yaml",
    "ksr": None,
    "skr": None,
    "log_ksr_contents": False,
    "log_skr_contents": False,
    "log_previous_skr_contents": False,
    "schema": "normal",
}

EXIT_CODES = {"success": 0, "interrupt": 1, "config": 2, "fatal": 3}


def parse_args(defaults: dict) -> ArgsType:
    """
    Parse command line arguments.

    The KSR signer is mostly configured using the config file (--config), but
    some things such as output verbosity is settable using command line arguments.
    """
    parser = argparse.ArgumentParser(
        description=f"KSK request signer {__verbose_version__}",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Positional arguments
    parser.add_argument(
        "ksr",
        metavar="KSRFILE",
        type=str,
        default=defaults["ksr"],
        nargs="?",
        help="KSR request to process",
    )

    parser.add_argument(
        "skr",
        metavar="SKRFILE",
        type=str,
        default=defaults["skr"],
        nargs="?",
        help="SKR output filename",
    )
    # Optional arguments
    parser.add_argument(
        "--schema",
        dest="schema",
        metavar="NAME",
        type=str,
        default=defaults["schema"],
        help="Name of schema (defined in config) to follow",
    )
    parser.add_argument(
        "--previous_skr",
        dest="previous_skr",
        metavar="SKRFILE",
        type=str,
        default=defaults["previous_skr"],
        help="Path to the previous SKR to use for validation",
    )
    parser.add_argument(
        "--log-ksr",
        dest="log_ksr_contents",
        action="store_true",
        default=defaults["log_ksr_contents"],
        help="Log KSR contents",
    )
    parser.add_argument(
        "--log-skr",
        dest="log_skr_contents",
        action="store_true",
        default=defaults["log_skr_contents"],
        help="Log SKR contents",
    )
    parser.add_argument(
        "--log-previous-skr",
        dest="log_previous_skr_contents",
        action="store_true",
        default=defaults["log_previous_skr_contents"],
        help="Log previus SKR contents",
    )
    parser.add_argument(
        "--config",
        dest="config",
        metavar="CFGFILE",
        type=str,
        default=defaults["config"],
        help="Path to the KSR signer configuration file",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=defaults["debug"],
        help="Enable debug operation",
    )
    parser.add_argument(
        "--syslog",
        dest="syslog",
        action="store_true",
        default=defaults["syslog"],
        help="Enable syslog output",
    )
    parser.add_argument(
        "--force",
        dest="force",
        action="store_true",
        default=False,
        help="Don't ask for confirmation",
    )
    parser.add_argument(
        "--hsm",
        dest="hsm",
        metavar="HSM",
        type=str,
        default=None,
        help="HSM to operate on",
    )
    args = parser.parse_args()
    return args


def _previous_skr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.previous_skr:
        return str(args.previous_skr)
    return config.get_filename("previous_skr")


def _ksr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.ksr:
        return str(args.ksr)
    return config.get_filename("input_ksr")


def _skr_filename(args: ArgsType, config: KSKMConfig) -> Optional[str]:
    if args and args.skr:
        return str(args.skr)
    return config.get_filename("output_skr")


def ksrsigner(
    logger: logging.Logger, args: ArgsType, config: Optional[KSKMConfig] = None
) -> bool:
    """Parse KSR and previous SKR. Produce a new SKR."""
    #
    # Load configuration, if not provided already
    #
    if config is None:
        try:
            config = get_config(args.config)
        except FileNotFoundError:
            logging.critical("Configuration file %s not found", args.config)
            return False

    #
    # Prepare schema
    #
    try:
        schema = config.get_schema(args.schema)
    except KeyError:
        logging.critical("Schema '%s' not found", args.schema)
        return False

    #
    # Load the previous SKR
    #
    skr = None
    _previous_skr = _previous_skr_filename(args, config)
    if _previous_skr:
        skr = kskm.skr.load_skr(
            _previous_skr,
            config.response_policy,
            log_contents=args.log_previous_skr_contents,
        )
        logger.info("Previous SKR:")
        for x in format_bundles_for_humans(skr.bundles):
            logger.info(x)

    #
    # Load the KSR request
    #
    _ksr_fn = _ksr_filename(args, config)
    if _ksr_fn is None:
        logger.error("No KSR filename specified")
        return False
    request = kskm.ksr.load_ksr(
        _ksr_fn, config.request_policy, log_contents=args.log_ksr_contents
    )
    logger.info("Request:")
    for x in format_bundles_for_humans(request.bundles):
        logger.info(x)

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    try:
        p11modules = kskm.misc.hsm.init_pkcs11_modules_from_dict(
            config.hsm, name=args.hsm
        )
    except Exception as e:
        logger.critical("HSM initialisation error: %s", str(e))
        return False

    #
    # Perform some checks that need both KSR, SKR and PKCS#11 modules
    #
    if skr is not None:
        check_skr_and_ksr(request, skr, config.request_policy, p11modules)
    else:
        logger.warning(
            "KSR-CHAIN: Previous SKR *NOT* loaded - daisy chain not validated"
        )
        logger.warning(
            "KSR-CHAIN: Previous SKR *NOT* loaded - presence of SKR(n-1) in HSM not validated"
        )

    if not args.force:
        print("")
        print("FILENAME:      ", request.xml_filename)
        print("SHA-256 HEX:   ", binascii.hexlify(request.xml_hash).decode())
        print("SHA-256 WORDS: ", " ".join(pgp_wordlist(request.xml_hash)))
        print("")
        ack = input(
            f'Sign KSR? Confirm with "Yes" (exactly) or anything else to abort: '
        )
        if ack.strip("\n") != "Yes":
            logger.warning(f"KSR signing aborted")
            return False

    #
    # Create a new SKR
    #
    new_skr = create_skr(request, schema, p11modules, config)
    if skr:
        check_last_skr_and_new_skr(skr, new_skr, config.request_policy)

    logger.info("Generated SKR:")
    for x in format_bundles_for_humans(new_skr.bundles):
        logger.info(x)

    _skr_fn = _skr_filename(args, config)
    output_skr_xml(new_skr, _skr_fn, log_contents=args.log_skr_contents)

    return True


def main() -> None:
    """Main program function."""
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_DEFAULTS)
        logger = get_logger(
            progname=progname, debug=args.debug, syslog=args.syslog, filelog=True
        ).getChild(__name__)
        res = ksrsigner(logger, args)
        if res is True:
            sys.exit(EXIT_CODES["success"])
        logging.critical("Fatal error, program stopped")
        sys.exit(EXIT_CODES["fatal"])
    except KeyboardInterrupt:
        logging.warning(f"Keyboard interrupt, program stopped")
        sys.exit(EXIT_CODES["interrupt"])
    except ConfigurationError as exc:
        logger = logging.getLogger("configuration")
        for message in str(exc).splitlines():
            logger.critical(message)
        logging.critical("Configuration error, program stopped")
        sys.exit(EXIT_CODES["config"])


if __name__ == "__main__":
    main()
