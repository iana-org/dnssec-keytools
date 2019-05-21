#!/usr/bin/env python3

"""
Key master utility.

Tool to create, delete, backup, restore keys as well as perform a key inventory.
"""

import argparse
import base64
import logging
import sys
from typing import List, Optional

from PyKCS11 import PyKCS11Error
import kskm
import kskm.misc
from kskm.common.config import KSKMConfig, get_config
from kskm.common.data import FlagsDNSKEY
from kskm.common.logging import get_logger
from kskm.keymaster.delete import key_delete, wrapkey_delete
from kskm.keymaster.inventory import key_inventory
from kskm.keymaster.keygen import generate_ec_key, generate_rsa_key, \
    generate_wrapping_key
from kskm.keymaster.wrap import key_backup, key_restore
from kskm.misc.hsm import KSKM_P11, KeyType, WrappingAlgorithm

SUPPORTED_ALGORITHMS = [str(x.name) for x in KeyType]
SUPPORTED_SIZES = [2048, 3072, 4096]
SUPPORTED_CURVES = ['secp256r1', 'secp384r1']
SUPPORTED_WRAPPING_ALGORITHMS = [x.value for x in WrappingAlgorithm]  # SoftHSM2 only supports AES


def keygen(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Generate new signing key."""
    logger.info('Generate key')
    flags = FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
    if args.key_alg == 'RSA':
        if args.key_size is None:
            raise argparse.ArgumentError(args.key_size, 'RSA key generation requires key size')
        generate_rsa_key(flags, args.key_size, p11modules)
    elif args.key_alg == 'EC':
        if args.key_crv is None:
            raise argparse.ArgumentError(args.key_crv, 'EC key generation requires curve')
        generate_ec_key(flags, args.key_crv, p11modules)
    pass


def keydel(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Delete signing key."""
    logger.info('Delete signing key')
    key_delete(args.key_label, p11modules)


def keybackup(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Backup key."""
    logger.info('Backup (export) key')
    # TODO: Make key_alg an Enum
    wrapped = key_backup(args.key_label, args.wrap_key_label, p11modules)
    if wrapped:
        print('WRAPPED: {}'.format(base64.b64encode(wrapped)))


def keyrestore(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Restore key."""
    logger.info('Restore (import) key')
    alg = WrappingAlgorithm[args.key_alg]
    if key_restore(wrapped_key, args.key_label, args.wrap_key_label, alg, p11modules):
        logger.info('Key restored successfully')


def wrapgen(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Generate new wrapping key."""
    logger.info('Generate wrapping key')
    alg = WrappingAlgorithm[args.key_alg]
    generate_wrapping_key(args.key_label, alg, p11modules)


def wrapdel(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Delete wrapping key."""
    logger.info('Delete wrapping key')
    wrapkey_delete(args.key_label, p11modules, args.force)


def inventory(args: argparse.Namespace, config: KSKMConfig, p11modules: KSKM_P11, logger: logging.Logger):
    """Show HSM inventory."""
    logger.info('Show HSM inventory')
    key_inventory(p11modules)


def main(progname='keymaster', args: Optional[List[str]] = None, config: Optional[KSKMConfig] = None) -> bool:
    """Main function."""
    parser = argparse.ArgumentParser(description='Keymaster')

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
    # TODO: pass in label, or generate it from current time like the old tool does?
    # TODO: set CKA_ID?
    parser_keygen.add_argument('--label',
                               dest='key_label',
                               metavar='LABEL',
                               type=str,
                               required=True,
                               help='Key label')
    parser_keygen.add_argument('--algorithm',
                               dest='key_alg',
                               metavar='ALGORITHM',
                               type=str,
                               choices=SUPPORTED_ALGORITHMS,
                               required=True,
                               help='Key algorithm')
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
    # TODO: Add option to identify HSM, if multiple are configured?
    # TODO: Add option to specify slot, instead of just picking the first one?
    # TODO: DNSKEY flags as option? Affects generated label.

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

    parser_keyrestore = subparsers.add_parser('restore')
    parser_keyrestore.set_defaults(func=keyrestore)
    parser_keyrestore.add_argument('--label',
                                   dest='key_label',
                                   metavar='LABEL',
                                   type=str,
                                   required=True,
                                   help='Restore (import) key label')
    parser_keyrestore.add_argument('--wrap-label',
                                   dest='wrap_key_label',
                                   metavar='LABEL',
                                   type=str,
                                   required=True,
                                   help='Wrapping key label')

    args = parser.parse_args(args=args)
    logger = get_logger(progname, debug=args.debug, syslog=False)

    #
    # Load configuration, if not provided already
    #
    if config is None:
        try:
            config = get_config(args.config)
        except FileNotFoundError as exc:
            logger.critical(str(exc))
            return False

    #
    # Initialise PKCS#11 modules (HSMs)
    #
    p11modules = kskm.misc.hsm.init_pkcs11_modules_from_dict(config.hsm, rw_session=True)

    if len(p11modules) <=0:
        logger.critical("No HSM configured")
        return False

    try:
        mode_function = args.func
    except AttributeError:
        parser.print_help()
        return False

    try:
        return mode_function(args, config, p11modules, logger)
    except PyKCS11Error as exc:
        logger.critical(str(exc))
        return False
    except argparse.ArgumentError as exc:
        parser.error(exc.message)


if __name__ == '__main__':
    try:
        res = main()
        if res is True:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
