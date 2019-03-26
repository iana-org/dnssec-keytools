#!/usr/bin/env python3

import argparse
import logging

# TODO: Key generator
# - generate new RSA/EC key
# - export key as partial RFC 7958 (kskm.ta.data.KeyDigest)

SUPPORTED_ALGORITMS = ["RSA", "EC"]
SUPPORTED_SIZES = [2048]
SUPPORTED_CURVES = ['secp256r1', 'secp384r1']


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description='KSK Generator')

    parser.add_argument('--hsm_config_dir',
                        dest='hsm_config_dir',
                        metavar='DIR', type=str,
                        help='Path to HSM configuration files')
    parser.add_argument('--token',
                        dest='token_label',
                        metavar='LABEL',
                        type=str,
                        required=True,
                        help='HSM for generated KSK')
    parser.add_argument('--label',
                        dest='key_label',
                        metavar='LABEL',
                        type=str,
                        required=True,
                        help='Label for generated key')
    parser.add_argument('--algorithm',
                        dest='key_algo',
                        metavar='ALGORITHM',
                        type=str,
                        choices=SUPPORTED_ALGORITMS,
                        required=True,
                        help='Key algorithm')
    parser.add_argument('--size',
                        dest='key_size',
                        metavar='SIZE',
                        type=int,
                        choices=SUPPORTED_SIZES,
                        required=False,
                        help='Key size')
    parser.add_argument('--crv',
                        dest='key_crv',
                        metavar='CURVE',
                        type=str,
                        choices=SUPPORTED_CURVES,
                        required=False,
                        help='Key curve')
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)




if __name__ == "__main__":
    main()
