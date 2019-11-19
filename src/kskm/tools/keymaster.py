#!/usr/bin/env python3

"""
Key master utility.

Tool to create, delete, backup, restore keys as well as perform a key inventory.
"""

# Possible future enhancements:
#
# pass in label, or generate it from current time (like old tool)
# set CKA_ID
# add option to identify HSM if multiple are configured
# add option to specify slot, instead of just picking the first one
# DNSKEY flags as option? Affects generated label.
# Allow choosing RSA exponent? As of now, this will default to 65537.

import argparse
import logging
import sys
from typing import List, Optional

import yaml
from PyKCS11 import PyKCS11Error

import kskm
import kskm.misc
from kskm.common.config import ConfigurationError, KSKMConfig, get_config
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.ecdsa_utils import algorithm_to_curve, is_algorithm_ecdsa
from kskm.common.logging import get_logger
from kskm.common.rsa_utils import is_algorithm_rsa
from kskm.keymaster.delete import key_delete, wrapkey_delete
from kskm.keymaster.inventory import key_inventory
from kskm.keymaster.keygen import (generate_ec_key, generate_rsa_key,
                                   generate_wrapping_key)
from kskm.keymaster.wrap import (WrappedKey, WrappedKeyRSA, key_backup,
                                 key_restore)
from kskm.misc.hsm import KSKM_P11, KeyType, WrappingAlgorithm

SUPPORTED_ALGORITHMS = [str(x.name) for x in KeyType]
SUPPORTED_SIZES = [2048, 3072, 4096]
SUPPORTED_CURVES = ['secp256r1', 'secp384r1']
SUPPORTED_WRAPPING_ALGORITHMS = [x.value for x in WrappingAlgorithm]  # SoftHSM2 only supports AES


def keygen(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Generate new signing key."""
    logger.info('Generate key')
    flags = FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
    dnssec_alg = AlgorithmDNSSEC[args.key_alg]
    if is_algorithm_rsa(dnssec_alg):
        if args.key_size is None:
            raise argparse.ArgumentError(args.key_size, 'RSA key generation requires key size')
        p11key = generate_rsa_key(flags, args.key_size, p11modules, label=args.key_label)
    elif is_algorithm_ecdsa(dnssec_alg):
        crv = algorithm_to_curve(dnssec_alg)
        p11key = generate_ec_key(flags, crv, p11modules, label=args.key_label)
    else:
        raise ValueError(f'Unknown key algorithm {repr(args.key_alg)}')

    if not p11key or not p11key.public_key:
        raise RuntimeError('No public key returned by key generation')

    # Calculate the DNSSEC key tag of the new key and look for a collision in the configuration
    key_tags: List[int] = []
    _key = public_key_to_dnssec_key(key=p11key.public_key,
                                    key_identifier=p11key.label,
                                    algorithm=AlgorithmDNSSEC[args.key_alg],
                                    flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value,
                                    ttl=config.ksk_policy.ttl,
                                    )
    logger.info(f'Generated key {p11key.label} has key tag {_key.key_tag} for algorithm={_key.algorithm}, '
                f'flags=0x{_key.flags:x}')
    key_tags += [_key.key_tag]
    _key = public_key_to_dnssec_key(key=p11key.public_key,
                                    key_identifier=p11key.label,
                                    algorithm=AlgorithmDNSSEC[args.key_alg],
                                    flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value | FlagsDNSKEY.REVOKE.value,
                                    ttl=config.ksk_policy.ttl,
                                    )
    logger.info(f'Generated key {p11key.label} has key tag {_key.key_tag} with the REVOKE bit set '
                f'(flags 0x{_key.flags:x})')
    key_tags += [_key.key_tag]

    for _name, ksk in config.ksk_keys.items():
        if ksk.key_tag in key_tags:
            logger.error(f'Generated key {p11key.label} has key tags {key_tags} matching '
                         f'KSK key in configuration: {ksk}')
            raise RuntimeError('Key tag collision detected')

    return True


def keydel(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Delete signing key."""
    logger.info('Delete signing key')
    key_delete(args.key_label, p11modules)
    return True


def keybackup(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Backup key."""
    logger.info('Backup (export) key')
    wrapped_key = key_backup(args.key_label, args.wrap_key_label, p11modules)
    if not wrapped_key:
        return False
    with open(args.outfile, 'w') as fd:
        fd.write('---\n')
        yaml.safe_dump(wrapped_key.to_dict(), fd)
    logger.info(f'Wrote wrapped key to file {args.outfile}')
    return True


def keyrestore(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Restore key."""
    logger.info('Restore (import) key')
    with open(args.infile, 'r') as fd:
        data = yaml.safe_load(fd)
    if data.get('key_type') == 'RSA':
        wrapped_key = WrappedKeyRSA.from_dict(data)
    else:
        wrapped_key = WrappedKey.from_dict(data)
    logger.info(f'Loaded wrapped key: {wrapped_key}')
    if key_restore(wrapped_key, p11modules):
        logger.info('Key restored successfully')
    return True


def wrapgen(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Generate new wrapping key."""
    logger.info('Generate wrapping key')
    alg = WrappingAlgorithm(args.key_alg)
    generate_wrapping_key(args.key_label, alg, p11modules)
    return True


def wrapdel(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Delete wrapping key."""
    logger.info('Delete wrapping key')
    wrapkey_delete(args.key_label, p11modules, args.force)
    return True


def inventory(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger) -> bool:
    """Show HSM inventory."""
    logger.info('Show HSM inventory')
    inv = key_inventory(p11modules, config)
    inv_str = '\n'.join(inv)
    logger.info(f'Key inventory:\n{inv_str}')

    return True


def main(progname: str = 'keymaster', argv: Optional[List[str]] = None, config: Optional[KSKMConfig] = None) -> bool:
    """Main function."""
    parser = argparse.ArgumentParser(description='Keymaster',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     )

    parser.add_argument('--config',
                        dest='config',
                        metavar='CFGFILE',
                        type=str,
                        default='ksrsigner.yaml',
                        help='Path to the KSR signer configuration file',
                        )
    parser.add_argument('--hsm',
                        dest='hsm',
                        metavar='HSM',
                        type=str,
                        help='HSM to operate on',
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        default=False,
                        help='Enable debug operation',
                        )

    subparsers = parser.add_subparsers()

    parser_inventory = subparsers.add_parser('inventory')
    parser_inventory.set_defaults(func=inventory)

    parser_keygen = subparsers.add_parser('keygen')
    parser_keygen.set_defaults(func=keygen)

    # Make a list of DNSSEC algorithms we allow generating keys for. RSASHA1 is obsoleted.
    valid_algorithms = [x.name for x in AlgorithmDNSSEC if x.name != 'RSASHA1' and
                        (is_algorithm_rsa(x) or is_algorithm_ecdsa(x))]
    parser_keygen.add_argument('--label',
                               dest='key_label',
                               metavar='LABEL',
                               type=str,
                               required=False,
                               help='Key label')
    parser_keygen.add_argument('--algorithm',
                               dest='key_alg',
                               metavar='ALGORITHM',
                               type=str,
                               choices=valid_algorithms,
                               required=True,
                               help='DNSSEC Key algorithm')
    parser_keygen.add_argument('--size',
                               dest='key_size',
                               metavar='BITS',
                               type=int,
                               choices=SUPPORTED_SIZES,
                               required=False,
                               help='Key size')
    parser_keygen.add_argument('--curve',
                               dest='key_crv',
                               metavar='CURVE',
                               type=str,
                               choices=SUPPORTED_CURVES,
                               required=False,
                               help='Key curve')

    parser_wrapgen = subparsers.add_parser('wrapgen')
    parser_wrapgen.set_defaults(func=wrapgen)
    parser_wrapgen.add_argument('--label',
                                dest='key_label',
                                metavar='LABEL',
                                type=str,
                                required=True,
                                help='Key label')
    parser_wrapgen.add_argument('--algorithm',
                                dest='key_alg',
                                metavar='ALGORITHM',
                                type=str,
                                choices=SUPPORTED_WRAPPING_ALGORITHMS,
                                required=True,
                                help='Wrapping key algorithm')

    parser_keydel = subparsers.add_parser('keydelete')
    parser_keydel.set_defaults(func=keydel)
    parser_keydel.add_argument('--label',
                               dest='key_label',
                               metavar='LABEL',
                               type=str,
                               required=True,
                               help='Key label')
    parser_keydel.add_argument('--force',
                               dest='force',
                               action='store_true',
                               default=False,
                               help='Don\'t ask for confirmation',
                               )

    parser_wrapdel = subparsers.add_parser('wrapdelete')
    parser_wrapdel.set_defaults(func=wrapdel)
    parser_wrapdel.add_argument('--label',
                                dest='key_label',
                                metavar='LABEL',
                                type=str,
                                required=True,
                                help='Key label')
    parser_wrapdel.add_argument('--force',
                                dest='force',
                                action='store_true',
                                default=False,
                                help='Don\'t ask for confirmation',
                                )

    parser_keybackup = subparsers.add_parser('backup')
    parser_keybackup.set_defaults(func=keybackup)
    parser_keybackup.add_argument('--label',
                                  dest='key_label',
                                  metavar='LABEL',
                                  type=str,
                                  required=True,
                                  help='Backup (export) key label')
    parser_keybackup.add_argument('--wrap-label',
                                  dest='wrap_key_label',
                                  metavar='LABEL',
                                  type=str,
                                  required=True,
                                  help='Wrapping key label')
    parser_keybackup.add_argument('--outfile',
                                  dest='outfile',
                                  metavar='FILE',
                                  type=str,
                                  required=True,
                                  help='Filename to write wrapped key to')

    parser_keyrestore = subparsers.add_parser('restore')
    parser_keyrestore.set_defaults(func=keyrestore)
    parser_keyrestore.add_argument('--wrap-label',
                                   dest='wrap_key_label',
                                   metavar='LABEL',
                                   type=str,
                                   required=True,
                                   help='Wrapping key label')
    parser_keyrestore.add_argument('--infile',
                                   dest='infile',
                                   metavar='FILE',
                                   type=str,
                                   required=True,
                                   help='Filename to read wrapped key from')

    args = parser.parse_args(args=argv)
    logger = get_logger(progname=progname, debug=args.debug, syslog=False, filelog=True).getChild(__name__)

    #
    # Load configuration, if not provided already
    #
    if config is None:
        try:
            config = get_config(args.config)
        except FileNotFoundError as exc:
            logger.critical(str(exc))
            return False
        except ConfigurationError as exc:
            logger = logging.getLogger('configuration')
            for message in str(exc).splitlines():
                logger.critical(message)
            return False

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    try:
        p11modules = kskm.misc.hsm.init_pkcs11_modules_from_dict(config.hsm, rw_session=True)
    except Exception as e:
        logger.critical("HSM initialisation error: %s", str(e))
        return False

    if len(p11modules) <= 0:
        logger.critical("No HSM configured")
        return False

    try:
        mode_function = args.func
    except AttributeError:
        parser.print_help()
        return False

    try:
        res = mode_function(args, config, p11modules, logger)
        if res is True:
            sys.exit(0)
    except PyKCS11Error as exc:
        logger.critical(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)

    sys.exit(1)


if __name__ == "__main__":
    main()
