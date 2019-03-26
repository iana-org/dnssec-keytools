#!/usr/bin/env python3

import hashlib
import sys
from kskm.tools_common.wordlist import pgp_wordlist


message = sys.stdin.read().encode()
m = hashlib.new('sha256')
m.update(message)
hexdigest = m.hexdigest()
words = pgp_wordlist(m.digest())

print(f"SHA-256:    {hexdigest}")
print(f"PGP Words:  {' '.join(words)}")
