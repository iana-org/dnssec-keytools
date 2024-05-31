"""DNSSEC protocol specific functions."""

import base64
import struct

from kskm.common.data import AlgorithmDNSSEC, Key
from kskm.common.public_key import KSKM_PublicKey

__author__ = "ft"


def key_to_rdata(key: Key) -> bytes:
    """Return key in DNS RDATA format (RFC 4034)."""
    header = struct.pack(
        "!HBB",
        key.flags,
        key.protocol,
        key.algorithm.value,
    )
    pubkey = base64.b64decode(key.public_key)
    return header + pubkey


def calculate_key_tag(key: Key) -> int:
    """
    Calculate DNSSEC key tag from RDATA.

    The algorithm to do this is found in RFC 4034, Appendix B.
    """
    rdata = key_to_rdata(key)

    _odd = False
    _sum = 0
    for this in rdata:
        if _odd:
            _sum += this
        else:
            _sum += this << 8
        _odd = not _odd
    return ((_sum & 0xFFFF) + (_sum >> 16)) & 0xFFFF


def public_key_to_dnssec_key(
    pubkey: bytes,
    key_identifier: str,
    algorithm: AlgorithmDNSSEC,
    ttl: int,
    flags: int,
) -> Key:
    """Make a Key instance from an KSKM_PublicKey, and some other values."""
    _key = Key(
        algorithm=algorithm,
        flags=flags,
        key_identifier=key_identifier,
        protocol=3,  # Always 3 for DNSSEC
        ttl=ttl,
        key_tag=0,  # will calculate this below
        public_key=pubkey,
    )
    key_tag = calculate_key_tag(_key)
    return _key.replace(key_tag=key_tag)
