#!/usr/bin/env python3

"""
Key master utility.

Tool to create, delete, backup, restore keys as well as perform a key inventory.
"""

import argparse
import logging

logger = logging.getLogger(__name__)

SUPPORTED_ALGORITMS = ["RSA", "EC"]
SUPPORTED_SIZES = [2048]
SUPPORTED_CURVES = ['secp256r1', 'secp384r1']


def keygen(args: argparse.Namespace):
    """Generate new signing key."""
    logger.info("Generate key")
    pass


def wrapgen(args: argparse.Namespace):
    """Generate new wrapping key."""
    logger.info("Generate wrapping key")
    pass


def keydel(args: argparse.Namespace):
    """Delete signing key."""
    logger.info("Delete signing key")
    pass


def wrapdel(args: argparse.Namespace):
    """Delete wrapping key."""
    logger.info("Delete wrapping key")
    pass


def keybackup(args: argparse.Namespace):
    """Backup key."""
    logger.info("Backup (export) key")
    pass


def keyrestore(args: argparse.Namespace):
    """Restore key."""
    logger.info("Restore (import) key")
    pass


def inventory(args: argparse.Namespace):
    """Show HSM inventory."""
    logger.info("Show HSM inventory")
    pass


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description='Keymaster')

    parser.add_argument('--config',
                        dest='config',
                        metavar='CFGFILE',
                        type=str,
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
                               choices=SUPPORTED_ALGORITMS,
                               required=True,
                               help='Key algorithm')
    parser_keygen.add_argument('--size',
                               dest='key_size',
                               metavar='SIZE',
                               type=int,
                               choices=SUPPORTED_SIZES,
                               required=False,
                               help='Key size')
    parser_keygen.add_argument('--crv',
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

    parser_keydel = subparsers.add_parser('keydelete')
    parser_keydel.set_defaults(func=keydel)
    parser_keydel.add_argument('--label',
                               dest='key_label',
                               metavar='LABEL',
                               type=str,
                               required=True,
                               help='Key label')

    parser_wrapdel = subparsers.add_parser('wrapdelete')
    parser_wrapdel.set_defaults(func=wrapdel)
    parser_wrapdel.add_argument('--label',
                                dest='key_label',
                                metavar='LABEL',
                                type=str,
                                required=True,
                                help='Key label')

    parser_keybackup = subparsers.add_parser('backup')
    parser_keybackup.set_defaults(func=keybackup)
    parser_keybackup.add_argument('--label',
                                  dest='key_label',
                                  metavar='LABEL',
                                  type=str,
                                  required=True,
                                  help='Backup (export) key label')
    parser_keybackup.add_argument('--wrap-label',
                                  dest='wrap-key_label',
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
                                   dest='wrap-key_label',
                                   metavar='LABEL',
                                   type=str,
                                   required=True,
                                   help='Wrapping key label')

    args = parser.parse_args()

    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
        exit(-1)


if __name__ == "__main__":
    main()
