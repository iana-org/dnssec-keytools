"""Various functions relating to the ECDSA algorithm."""
import base64
from dataclasses import dataclass, field
from enum import Enum

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyECDSA
from kskm.common.public_key import KSKM_PublicKey

__author__ = "ft"


class ECCurve(Enum):
    """ECC Curves."""

    P256 = "secp256r1"
    P384 = "secp384r1"


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
        """Return key as string."""
        return f"alg=EC bits={self.bits} curve={self.curve.value}"


def is_algorithm_ecdsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is one of the ECDSA algorithms."""
    return alg in [
        AlgorithmDNSSEC.ECDSAP256SHA256,
        AlgorithmDNSSEC.ECDSAP384SHA384,
    ]


def algorithm_to_curve(alg: AlgorithmDNSSEC) -> ECCurve:
    """Return EC Curve of ECDSA key."""
    if alg in ALGORITHM_TO_CURVE:
        return ALGORITHM_TO_CURVE[alg]
    raise ValueError("Unsupported algorithm")


def parse_signature_policy_ecdsa(data: dict) -> AlgorithmPolicyECDSA:
    """
    Parse ECDSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data["attrs"]["algorithm"]))
    attrs = data["value"]["ECDSA"]["attrs"]
    ecdsa = AlgorithmPolicyECDSA(algorithm=attr_alg, bits=int(attrs["size"]),)
    return ecdsa


def encode_ecdsa_public_key(key: KSKM_PublicKey_ECDSA) -> bytes:
    """Convert the internal representation for a public ECDSA key to bytes."""
    return base64.b64encode(key.q)


def decode_ecdsa_public_key(key: bytes, curve: ECCurve) -> KSKM_PublicKey_ECDSA:
    """Parse bytes to the internal representation of an ECDSA key."""
    q = base64.b64decode(key)
    return KSKM_PublicKey_ECDSA(curve=curve, bits=len(q) * 8, q=q)


def ecdsa_public_key_without_prefix(
    public_key: bytes, algorithm: AlgorithmDNSSEC
) -> bytes:
    """
    Normalise ECDSA public keys by removing the common 0x04 prefix byte.

    Depending on source of the public key, it might be prefixed by the 0x04 byte used in
    SEC 1 encoding to signify a complete (x,y). If the size is not what we would have expected
    for a particular algorithm, and the first byte is 0x04 we remove it.
    """
    size = get_ecdsa_pubkey_size(public_key)
    if size != expected_ecdsa_key_size(algorithm):
        # Current size indicates there might be a prefix byte, check if the first byte is an 0x04.
        # We could be more stringent here and only remove the 0x04 if it would result in the expected
        # amount of bytes, but the we get less readable error messages saying "Unexpected size 352 instead of 256"
        # whilst we now get "Unexpected size 384 instead of 256".
        if public_key[0] == 4:
            # _ec_point is an 0x04 prefix byte, and then both x and y points concatenated, so divide by 2
            return public_key[1:]
    return public_key


def get_ecdsa_pubkey_size(public_key: bytes) -> int:
    """Return ECDSA public key size."""
    # pubkey is both x and y points concatenated, so divide by 2
    return len(public_key) * 8 // 2


def expected_ecdsa_key_size(algorithm: AlgorithmDNSSEC) -> int:
    """Return expected ECDSA public key size."""
    _expected = {
        AlgorithmDNSSEC.ECDSAP256SHA256: 256,
        AlgorithmDNSSEC.ECDSAP384SHA384: 384,
    }
    if algorithm not in _expected:
        raise ValueError(f"Unhandled ECDSA algorithm {algorithm}")
    return _expected[algorithm]
