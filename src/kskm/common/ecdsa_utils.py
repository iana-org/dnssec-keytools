"""Various functions relating to the ECDSA algorithm."""
import base64
from dataclasses import dataclass, field

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyECDSA, KSKM_PublicKey

__author__ = 'ft'


@dataclass(frozen=True)
class ECDSAPublicKeyData(KSKM_PublicKey):
    """A parsed DNSSEC ECDSA public key."""

    q: bytes = field(repr=False)
    algorithm: AlgorithmDNSSEC


def is_algorithm_ecdsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is one of the ECDSA algorithms."""
    return alg in [AlgorithmDNSSEC.ECDSAP256SHA256,
                   AlgorithmDNSSEC.ECDSAP384SHA384,
                   ]


def parse_signature_policy_ecdsa(data: dict) -> AlgorithmPolicyECDSA:
    """
    Parse ECDSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data['attrs']['algorithm']))
    attrs = data['value']['ECDSA']['attrs']
    dsa = AlgorithmPolicyECDSA(bits=int(attrs['size']),
                               algorithm=attr_alg,
                               )
    return dsa


def encode_ecdsa_public_key(key: ECDSAPublicKeyData) -> bytes:
    return base64.b64encode(key.q)


def decode_ecdsa_public_key(key: bytes, algorithm: AlgorithmDNSSEC) -> ECDSAPublicKeyData:
    q = base64.b64decode(key)
    return ECDSAPublicKeyData(bits=len(q) * 8, q=q, algorithm=algorithm)
