"""
SHA-256 PGP Words calculator.

Command line to to calculate SHA-256 hash of STDIN and present result as hex
digest and PGP wordlist. Also able to process one or more files specified on
the command line.
"""


import argparse
import hashlib
import sys
from typing import Optional

from kskm.common.wordlist import pgp_wordlist
from kskm.version import __verbose_version__


def words(filename: Optional[str] = None) -> None:
    """Output PGP words from file or STDIN."""
    if filename is not None:
        print(f"Filename:   {filename}")
        with open(filename, "rb") as input_file:
            message = input_file.read()
    else:
        message = sys.stdin.buffer.read()

    m = hashlib.new("sha256")
    m.update(message)
    hexdigest = m.hexdigest()
    pgp_words = pgp_wordlist(m.digest())

    print(f"SHA-256:    {hexdigest}")
    print(f"PGP Words:  {' '.join(pgp_words)}")

    if filename is not None:
        print()


def main():
    """Main program function."""
    parser = argparse.ArgumentParser(
        description=f"SHA-256 PGP Words Calculator {__verbose_version__}",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "inputs", metavar="filename", type=str, nargs="*", help="Input file"
    )

    args = parser.parse_args()

    if args.inputs:
        for filename in args.inputs:
            words(filename)
    else:
        words()


if __name__ == "__main__":
    main()
