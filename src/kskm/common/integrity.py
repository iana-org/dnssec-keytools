"""Integrity checking helpers."""

import hashlib
from typing import List, Tuple

from kskm.common.wordlist import pgp_wordlist


def sha2wordlist(message: bytes) -> Tuple[str, List[str]]:
    """Create SHA-256 hexdigest and word list from bytes."""
    m = hashlib.new('sha256')
    m.update(message)
    hexdigest = m.hexdigest()
    words = pgp_wordlist(m.digest())
    return (hexdigest, words)


def checksum_bytes2str(message: bytes) -> str:
    """Format SHA-256 digest."""
    (hexdigest, words) = sha2wordlist(message)
    return f"SHA-256 {hexdigest} WORDS {' '.join(words)}"
