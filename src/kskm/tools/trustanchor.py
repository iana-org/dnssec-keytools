"""
Trust anchor key exporter.

  - export key as RFC 7958 trust anchor

for each key in the ksr signer configuration file:
  - fetch public key from HSM
  - check matching algorithm and key parameters
  - create keydigest using kskm.ta.data.KeyDigest
export kskm.ta.data.TrustAnchor to file
"""

import argparse
import logging
import os
import sys
import uuid
from argparse import Namespace as ArgsType
from pathlib import Path
from typing import Any, Mapping, NoReturn

from kskm.common.config import KSKMConfig, get_config
from kskm.common.data import FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.integrity import checksum_bytes2str
from kskm.common.logging import get_logger
from kskm.misc.hsm import get_p11_key, init_pkcs11_modules
from kskm.ta import TrustAnchor
from kskm.ta.data import KeyDigest
from kskm.ta.keydigest import create_trustanchor_keydigest
from kskm.tools import EXIT_CODES
from kskm.version import __verbose_version__

_DEFAULTS: Mapping[str, Any] = {
    "debug": False,
    "config": "ksrsigner.yaml",
}


def parse_args(arguments: list[str], defaults: Mapping[str, Any]) -> ArgsType:
    """
    Parse command line arguments.

    The KSR signer is mostly configured using the config file (--config), but
    some things such as output verbosity is settable using command line arguments.
    """
    parser = argparse.ArgumentParser(
        description=f"DNSSEC Trust Anchor exporter {__verbose_version__}",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Required arguments
    parser.add_argument(
        "--config",
        dest="config",
        metavar="CFGFILE",
        type=str,
        default=defaults["config"],
        help="Path to the KSR signer configuration file",
    )

    # Optional arguments
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=defaults["debug"],
        help="Enable debug operation",
    )
    parser.add_argument(
        "--trustanchor",
        dest="trustanchor",
        metavar="XMLFILE",
        type=str,
        help="Path to write trust anchor XML to",
    )
    parser.add_argument(
        "--id",
        dest="id",
        metavar="ID",
        type=str,
        help="Trust anchor identifier",
    )
    parser.add_argument(
        "--hsm",
        dest="hsm",
        default=None,
        metavar="HSM",
        type=str,
        help="HSM to operate on",
    )

    return parser.parse_args(args=arguments)


def _trustanchor_filename(args: ArgsType | None, config: KSKMConfig) -> Path | None:
    if args and args.trustanchor:
        return Path(args.trustanchor)
    return config.filenames.output_trustanchor


def output_trustanchor_xml(ta: TrustAnchor, output_filename: Path | None, logger: logging.Logger) -> None:
    """Return trust anchor as XML."""
    xml = ta.to_xml_doc()
    if output_filename:
        xml_bytes = xml.encode()
        with open(output_filename, "wb") as fd:
            fd.write(xml_bytes)
        logger.info(f"Wrote trust anchor to file {output_filename} {checksum_bytes2str(xml_bytes)}")
    else:
        print(xml)


def trustanchor(
    logger: logging.Logger,
    args: ArgsType,
    config: KSKMConfig | None = None,
) -> EXIT_CODES:
    """Main entry point for generating trust anchors and writing them (as XML) to a file."""
    #
    # Load configuration, if not provided already
    #
    if config is None:
        _filename = args.config if args else None
        try:
            config = get_config(_filename)
        except FileNotFoundError as exc:
            logger.critical(str(exc))
            return EXIT_CODES.fatal

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    p11modules = init_pkcs11_modules(config, name=args.hsm)

    key_digests: set[KeyDigest] = set()

    for ksk in config.ksk_keys.values():
        p11key = get_p11_key(ksk.label, p11modules, public=True)
        if not p11key or not p11key.public_key:
            logger.warning(f"KSK key with label {ksk.label} could not be loaded using PKCS#11")
            continue
        _key = public_key_to_dnssec_key(
            public_key=p11key.public_key,
            key_identifier=ksk.label,
            algorithm=ksk.algorithm,
            flags=FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value,
            ttl=config.ksk_policy.ttl,
        )
        this = create_trustanchor_keydigest(ksk, _key)
        key_digests.add(this)

    ta = TrustAnchor(
        id=args.id or str(uuid.uuid4()),
        source="http://data.iana.org/root-anchors/root-anchors.xml",
        zone=".",
        key_digests=key_digests,
    )

    output_trustanchor_xml(ta, _trustanchor_filename(args, config), logger)

    return EXIT_CODES.success


def main(progname: str, arguments: list[str]) -> EXIT_CODES:
    """Main program function."""
    args = parse_args(arguments=arguments, defaults=_DEFAULTS)
    logger = get_logger(progname=progname, debug=args.debug, syslog=False, filelog=True).getChild(__name__)
    return trustanchor(logger, args)


def script_entrypoint() -> NoReturn:
    """Script entrypoint for this tool"""
    try:
        progname = os.path.basename(sys.argv[0])
        res = main(progname=progname, arguments=sys.argv[1:])
        sys.exit(res.value)
    except KeyboardInterrupt:
        sys.exit(EXIT_CODES.interrupt.value)


if __name__ == "__main__":
    # Run the script entrypoint if executed manually
    script_entrypoint()
