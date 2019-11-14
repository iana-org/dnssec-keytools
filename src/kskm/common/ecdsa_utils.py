"""Various functions relating to the ECDSA algorithm."""
import base64
from dataclasses import dataclass, field
from enum import Enum

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyECDSA
from kskm.common.public_key import KSKM_PublicKey

__author__ = 'ft'

class ECCurve(Enum):
    P256 = 'secp256r1'
    P384 = 'secp384r1'

ALGORITHM_TO_CURVE = {
    AlgorithmDNSSEC.ECDSAP256SHA256: ECCurve.P256,
    AlgorithmDNSSEC.ECDSAP384SHA384: ECCurve.P384,
}


@dataclass(frozen=True)
class KSKM_PublicKey_ECDSA(KSKM_PublicKey):
    """A parsed DNSSEC ECDSA public key."""

    q: bytes = field(repr=False)
    curve: ECCurve

    def __str__(self) -> str:
        return f"alg=EC bits={self.bits} curve={self.curve.value}"


def is_algorithm_ecdsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is one of the ECDSA algorithms."""
    return alg in [AlgorithmDNSSEC.ECDSAP256SHA256,
                   AlgorithmDNSSEC.ECDSAP384SHA384,
                   ]


def algorithm_to_curve(alg: AlgorithmDNSSEC) -> ECCurve:
    """Return EC Curve of ECDSA key"""
    if alg in ALGORITHM_TO_CURVE:
        return ALGORITHM_TO_CURVE[alg]
    else:
        raise ValueError("Unsupported algorithm")


def parse_signature_policy_ecdsa(data: dict) -> AlgorithmPolicyECDSA:
    """
    Parse ECDSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data['attrs']['algorithm']))
    attrs = data['value']['ECDSA']['attrs']
    ecdsa = AlgorithmPolicyECDSA(algorithm=attr_alg,
                                 bits=int(attrs['size']),
                                 )
    return ecdsa


def encode_ecdsa_public_key(key: KSKM_PublicKey_ECDSA) -> bytes:
    """Convert the internal representation for a public ECDSA key to bytes."""
    return base64.b64encode(key.q)


def decode_ecdsa_public_key(key: bytes, curve: ECCurve) -> KSKM_PublicKey_ECDSA:
    """Parse bytes to the internal representation of an ECDSA key."""
    q = base64.b64decode(key)
    return KSKM_PublicKey_ECDSA(curve=curve,
                                bits=len(q) * 8,
                                q=q)
