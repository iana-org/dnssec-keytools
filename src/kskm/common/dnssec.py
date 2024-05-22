"""DNSSEC protocol specific functions."""

import base64
import struct

from kskm.common.data import AlgorithmDNSSEC, Key
from kskm.common.ecdsa_utils import (
    KSKM_PublicKey_ECDSA,
    algorithm_to_curve,
    encode_ecdsa_public_key,
)
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import KSKM_PublicKey_RSA, encode_rsa_public_key

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
    key: KSKM_PublicKey,
    key_identifier: str,
    algorithm: AlgorithmDNSSEC,
    ttl: int,
    flags: int,
) -> Key:
    """Make a Key instance from an KSKM_PublicKey, and some other values."""
    if isinstance(key, KSKM_PublicKey_RSA):
        pubkey = encode_rsa_public_key(key)
    elif isinstance(key, KSKM_PublicKey_ECDSA):
        if algorithm_to_curve(algorithm) != key.curve:
            raise ValueError(
                f"Can't make {algorithm} key out of public key "
                f"{key_identifier} with curve {key.curve}"
            )
        pubkey = encode_ecdsa_public_key(key)
    else:
        raise RuntimeError(f"Unrecognised key {key}")
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
