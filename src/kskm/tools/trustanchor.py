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

import kskm
from kskm.common.config import KSKMConfig, get_config
from kskm.common.data import FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.integrity import checksum_bytes2str
from kskm.common.logging import get_logger
from kskm.misc.hsm import get_p11_key
from kskm.ta import TrustAnchor
from kskm.ta.keydigest import create_trustanchor_keydigest
from kskm.version import __verbose_version__

_DEFAULTS = {
    "debug": False,
    "config": "ksrsigner.yaml",
}


def parse_args(defaults: dict) -> ArgsType:
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

    args = parser.parse_args()
    return args


def _trustanchor_filename(args: ArgsType | None, config: KSKMConfig) -> str | None:
    if args and args.trustanchor:
        return str(args.trustanchor)
    return config.get_filename("output_trustanchor")


def output_trustanchor_xml(
    ta: TrustAnchor, output_filename: str | None, logger: logging.Logger
) -> None:
    """Return trust anchor as XML."""
    xml = ta.to_xml_doc()
    if output_filename:
        xml_bytes = xml.encode()
        with open(output_filename, "wb") as fd:
            fd.write(xml_bytes)
        logger.info(
            f"Wrote trust anchor to file {output_filename} {checksum_bytes2str(xml_bytes)}"
        )
    else:
        print(xml)


def trustanchor(
    logger: logging.Logger,
    args: ArgsType,
    config: KSKMConfig | None = None,
) -> bool:
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
            sys.exit(-1)

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    p11modules = kskm.misc.hsm.init_pkcs11_modules_from_dict(config.hsm, name=args.hsm)

    keydigests = set()

    for _name, ksk in config.ksk_keys.items():
        p11key = get_p11_key(ksk.label, p11modules, public=True)
        if not p11key or not p11key.public_key:
            logger.warning(
                f"KSK key with label {ksk.label} could not be loaded using PKCS#11"
            )
            continue
        _key = public_key_to_dnssec_key(
            key=p11key.public_key,
            key_identifier=ksk.label,
            algorithm=ksk.algorithm,
            flags=FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value,
            ttl=config.ksk_policy.ttl,
        )
        this = create_trustanchor_keydigest(ksk, _key)
        keydigests.add(this)

    ta = TrustAnchor(
        id=args.id or str(uuid.uuid4()),
        source="http://data.iana.org/root-anchors/root-anchors.xml",
        zone=".",
        keydigests=keydigests,
    )

    output_trustanchor_xml(ta, _trustanchor_filename(args, config), logger)

    return True


def main() -> None:
    """Main program function."""
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_DEFAULTS)
        logger = get_logger(
            progname=progname, debug=args.debug, syslog=False, filelog=True
        ).getChild(__name__)
        res = trustanchor(logger, args)
        if res is True:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
