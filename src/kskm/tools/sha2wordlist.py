#!/usr/bin/env python3
"""
SHA-256 PGP Words calculator.

Command line to to calculate SHA-256 hash of STDIN and present
result as hex digest and PGP wordlist.
"""

import hashlib
import sys
from kskm.common.wordlist import pgp_wordlist


message = sys.stdin.read().encode()
m = hashlib.new('sha256')
m.update(message)
hexdigest = m.hexdigest()
words = pgp_wordlist(m.digest())

print(f"SHA-256:    {hexdigest}")
print(f"PGP Words:  {' '.join(words)}")
