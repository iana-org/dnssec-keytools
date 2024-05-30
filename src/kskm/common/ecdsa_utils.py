"""Various functions relating to the ECDSA algorithm."""

import base64
from enum import Enum
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pydantic import Field

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyECDSA
from kskm.common.public_key import KSKM_PublicKey, algorithm_to_hash

__author__ = "ft"


class ECCurve(Enum):
    """ECC Curves."""

    P256 = "secp256r1"
    P384 = "secp384r1"


ALGORITHM_TO_CURVE = {
    AlgorithmDNSSEC.ECDSAP256SHA256: ECCurve.P256,
    AlgorithmDNSSEC.ECDSAP384SHA384: ECCurve.P384,
}


class KSKM_PublicKey_ECDSA(KSKM_PublicKey):
    """A parsed DNSSEC ECDSA public key."""

    q: bytes = Field(repr=False)
    curve: ECCurve

    def __str__(self) -> str:
        """Return key as string."""
        return f"alg=EC bits={self.bits} curve={self.curve.value}"

    def to_cryptography_pubkey(self) -> ec.EllipticCurvePublicKey:
        """Convert an KSKM_PublicKey_ECDSA into a 'cryptography' ec.EllipticCurvePublicKey."""
        q = self.q
        curve: object
        if self.curve == ECCurve.P256:
            curve = ec.SECP256R1()
            if len(q) == (256 // 8) * 2:
                # q is the bare x and y point, have to add a prefix of 0x04 (SEC 1: complete point (x,y))
                q = b"\x04" + q
        elif self.curve == ECCurve.P384:
            curve = ec.SECP384R1()
            if len(q) == (384 // 8) * 2:
                # q is the bare x and y point, have to add a prefix of 0x04 (SEC 1: complete point (x,y))
                q = b"\x04" + q
        else:
            raise RuntimeError(f"Don't know which curve to use for {self.curve.name}")
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, q)

    def verify_signature(
        self, signature: bytes, data: bytes, algorithm: AlgorithmDNSSEC
    ) -> None:
        """Verify a signature over 'data' using the 'cryptography' library."""
        pubkey = self.to_cryptography_pubkey()
        # OpenSSL (which is at the bottom of 'cryptography' expects ECDSA signatures to
        # be in RFC3279 format (ASN.1 encoded).
        _r, _s = signature[: len(signature) // 2], signature[len(signature) // 2 :]
        r = int.from_bytes(_r, byteorder="big")
        s = int.from_bytes(_s, byteorder="big")
        signature = encode_dss_signature(r, s)
        _ec_alg = ec.ECDSA(algorithm=algorithm_to_hash(algorithm))
        pubkey.verify(signature, data, _ec_alg)

    def to_algorithm_policy(self, algorithm: AlgorithmDNSSEC) -> AlgorithmPolicyECDSA:
        """Return an algorithm policy instance for this key."""
        if not is_algorithm_ecdsa(algorithm):
            raise ValueError(f"Algorithm mismatch: Expected ECDSA, got {algorithm}")

        raise RuntimeError("Creating ECDSA AlgorithmPolicy not implemented")

    @classmethod
    def decode_public_key(cls, key: bytes, algorithm: AlgorithmDNSSEC) -> Self:
        """Parse bytes to the internal representation of an ECDSA key."""
        q = base64.b64decode(key)
        curve = algorithm_to_curve(algorithm)
        return cls(curve=curve, bits=len(q) * 8, q=q)

    def encode_public_key(self, algorithm: AlgorithmDNSSEC) -> bytes:
        """Convert the internal representation for a public ECDSA key to bytes."""
        curve = algorithm_to_curve(algorithm)
        if curve != self.curve:
            raise ValueError(f"Curve mismatch: Expected {curve}, got {self.curve}")
        return base64.b64encode(self.q)



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


def parse_signature_policy_ecdsa(data: dict[str, Any]) -> AlgorithmPolicyECDSA:
    """
    Parse ECDSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data["attrs"]["algorithm"]))
    attrs = data["value"]["ECDSA"]["attrs"]
    ecdsa = AlgorithmPolicyECDSA(
        algorithm=attr_alg,
        bits=int(attrs["size"]),
    )
    return ecdsa



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
    if size != expected_ecdsa_key_size(algorithm):  # noqa
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
