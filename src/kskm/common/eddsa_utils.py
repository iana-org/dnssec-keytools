"""Various functions relating to the ECDSA algorithm."""

import base64
from enum import Enum
from hashlib import sha512, shake_256
from typing import Any, Final, Self

from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
from cryptography.hazmat.primitives.hashes import SHA512, SHAKE256
from pydantic import Field, ValidationInfo, field_validator

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyEdDSA
from kskm.common.public_key import KSKM_PublicKey

EdwardsCurvePublicKey = ed25519.Ed25519PublicKey | ed448.Ed448PublicKey

__author__ = "ft"


class EdCurve(Enum):
    """EC Edwards Curves."""

    Ed25519 = "Ed25519"
    Ed448 = "Ed448"


class KSKM_PublicKey_EdDSA(KSKM_PublicKey):
    """A parsed DNSSEC EdDSA public key."""

    q: bytes = Field(repr=False)
    curve: EdCurve

    algorithm_to_hash: Final[dict[AlgorithmDNSSEC, SHA512 | SHAKE256]] = {
        AlgorithmDNSSEC.ED25519: SHA512(),
        AlgorithmDNSSEC.ED448: SHAKE256(digest_size=114),
    }

    algorithm_to_curve: Final[dict[AlgorithmDNSSEC, EdCurve]] = {
        AlgorithmDNSSEC.ED25519: EdCurve.Ed25519,
        AlgorithmDNSSEC.ED448: EdCurve.Ed448,
    }

    @field_validator("algorithm")
    @classmethod
    def _check_algorithm(cls, value: AlgorithmDNSSEC) -> AlgorithmDNSSEC:
        if not is_algorithm_eddsa(value):
            raise ValueError(f"Algorithm mismatch: Expected EdDSA, got {value}")
        return value

    @field_validator("curve", mode="after")
    @classmethod
    def _check_curve(cls, v: EdCurve, info: ValidationInfo) -> EdCurve:
        if v != algorithm_to_curve(info.data["algorithm"]):
            raise ValueError(
                f"Curve mismatch: Expected {algorithm_to_curve(info.data['algorithm'])}, got {v}"
            )
        return v

    def __str__(self) -> str:
        """Return key as string."""
        return f"alg=EC bits={self.bits} curve={self.curve.value}"

    def to_cryptography_pubkey(self) -> EdwardsCurvePublicKey:
        """Convert an KSKM_PublicKey_EdDSA into a 'cryptography' ec.EllipticCurvePublicKey."""
        if self.curve == EdCurve.Ed25519:
            return ed25519.Ed25519PublicKey.from_public_bytes(self.q)
        elif self.curve == EdCurve.Ed448:
            return ed448.Ed448PublicKey.from_public_bytes(self.q)

        raise RuntimeError(f"Don't know which curve to use for {self.curve.name}")

    def verify_signature(self, signature: bytes, data: bytes) -> None:
        """Verify a signature over 'data' using the 'cryptography' library."""
        if self.algorithm == AlgorithmDNSSEC.ED25519:
            data = sha512(data).digest()
        elif self.algorithm == AlgorithmDNSSEC.ED448:
            # RFC 8080 section 4: An Ed448 signature consists of a 114-octet value
            data = shake_256(data).digest(114)

        pubkey = self.to_cryptography_pubkey()
        pubkey.verify(signature, data)

    def to_algorithm_policy(self) -> AlgorithmPolicyEdDSA:
        """Return an algorithm policy instance for this key."""
        raise RuntimeError("Creating EdDSA AlgorithmPolicy not implemented")

    @classmethod
    def decode_public_key(cls, key: bytes, algorithm: AlgorithmDNSSEC) -> Self:
        """Parse bytes to the internal representation of an EdDSA key."""
        curve = algorithm_to_curve(algorithm)
        return cls(curve=curve, bits=len(key) * 8, q=key, algorithm=algorithm)

    def encode_public_key(self) -> bytes:
        """Convert the internal representation for a public EdDSA key to bytes."""
        return base64.b64encode(self.q)


def is_algorithm_eddsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is one of the EdDSA algorithms."""
    return alg in [
        AlgorithmDNSSEC.ED25519,
        AlgorithmDNSSEC.ED448,
    ]


def algorithm_to_curve(alg: AlgorithmDNSSEC) -> EdCurve:
    """Return EC Curve of ECDSA key."""
    if alg in KSKM_PublicKey_EdDSA.algorithm_to_curve:
        return KSKM_PublicKey_EdDSA.algorithm_to_curve[alg]
    raise ValueError("Unsupported algorithm")


def parse_signature_policy_eddsa(
    data: dict[str, Any],
) -> AlgorithmPolicyEdDSA:
    """
    Parse EdDSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data["attrs"]["algorithm"]))
    attrs = data["value"]["EdDSA"]["attrs"]
    policy = AlgorithmPolicyEdDSA(
        algorithm=attr_alg,
        bits=int(attrs["size"]),
    )
    return policy


def eddsa_public_key_without_prefix(
    public_key: bytes, algorithm: AlgorithmDNSSEC
) -> bytes:
    """
    Normalise EdDSA public keys by removing the common 0x04 prefix byte.

    Depending on source of the public key, it might be prefixed by the 0x04 byte used in
    SEC 1 encoding to signify a complete (x,y). If the size is not what we would have expected
    for a particular algorithm, and the first byte is 0x04 we remove it.
    """
    size = get_eddsa_pubkey_size(public_key)
    if size != expected_eddsa_key_size(algorithm):  # noqa
        # Current size indicates there might be a prefix byte, check if the first byte is an 0x04.
        # We could be more stringent here and only remove the 0x04 if it would result in the expected
        # amount of bytes, but the we get less readable error messages saying "Unexpected size 352 instead of 256"
        # whilst we now get "Unexpected size 384 instead of 256".
        if public_key[0] == 4:
            # _ec_point is an 0x04 prefix byte, and then both x and y points concatenated, so divide by 2
            return public_key[1:]
    return public_key


def get_eddsa_pubkey_size(public_key: bytes) -> int:
    """Return EdDSA public key size."""
    return len(public_key) * 8


def expected_eddsa_key_size(algorithm: AlgorithmDNSSEC) -> int:
    """Return expected ECDSA public key size."""
    _expected = {
        AlgorithmDNSSEC.ED25519: 256,
        AlgorithmDNSSEC.ED448: 456,
    }
    if algorithm not in _expected:
        raise ValueError(f"Unhandled EdDSA algorithm {algorithm}")
    return _expected[algorithm]
