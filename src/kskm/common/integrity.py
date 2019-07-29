"""Integrity checking helpers."""

import binascii
import hashlib
from typing import List, Tuple

from kskm.common.wordlist import pgp_wordlist


def sha256(message: bytes) -> bytes:
    """Create SHA-256 digest from bytes."""
    return hashlib.sha256(message).digest()


def sha2wordlist(message: bytes) -> Tuple[str, List[str]]:
    """Create SHA-256 hexdigest and word list from bytes."""
    digest = sha256(message)
    hexdigest = binascii.hexlify(digest).decode()
    words = pgp_wordlist(digest)
    return (hexdigest, words)


def _format_digest(digest: bytes) -> str:
    """Format SHA-256 digest."""
    hexdigest = binascii.hexlify(digest).decode()
    words = pgp_wordlist(digest)
    return f"SHA-256 {hexdigest} WORDS {' '.join(words)}"


def checksum_bytes2str(message: bytes) -> str:
    """Format SHA-256 digest."""
    return _format_digest(sha256(message))
