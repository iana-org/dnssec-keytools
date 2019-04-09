"""DNSSEC protocol specific functions."""
import base64
import struct
from dataclasses import replace
from typing import Optional

from kskm.common.data import AlgorithmDNSSEC, Key, KSKM_PublicKey
from kskm.common.ecdsa_utils import ECDSAPublicKeyData, encode_ecdsa_public_key
from kskm.common.rsa_utils import RSAPublicKeyData, encode_rsa_public_key

__author__ = 'ft'


def key_to_rdata(key: Key) -> bytes:
    """Return key in DNS RDATA format."""
    header = struct.pack('!HBB',
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

    odd = False
    sum = 0
    for this in rdata:
        if odd:
            sum += this
        else:
            sum += this << 8
        odd = not odd
    return ((sum & 0xffff) + (sum >> 16)) & 0xffff


def public_key_to_dnssec_key(key: KSKM_PublicKey,
                             key_identifier: Optional[str], algorithm: AlgorithmDNSSEC,
                             ttl: int, flags: int) -> Key:
    """Make a Key instance from an RSAPublicKeyData, and some other values."""
    if isinstance(key, RSAPublicKeyData):
        pubkey = encode_rsa_public_key(key)
    elif isinstance(key, ECDSAPublicKeyData):
        pubkey = encode_ecdsa_public_key(key)
    else:
        raise RuntimeError(f'Unrecognised key {key}')
    _key = Key(algorithm=algorithm,
               flags=flags,
               key_identifier=key_identifier,
               protocol=3,  # Always 3 for DNSSEC
               ttl=ttl,
               key_tag=0,  # will calculate this below
               public_key=pubkey,
               )
    key_tag = calculate_key_tag(_key)
    return replace(_key, key_tag=key_tag)
