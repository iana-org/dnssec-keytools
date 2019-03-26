"""DNSSEC protocol specific functions."""
import struct
import base64

from kskm.common.data import Key

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
