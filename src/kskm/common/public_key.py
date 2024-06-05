"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC, abstractmethod
from typing import Self

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from kskm.common.data import (
    AlgorithmDNSSEC,
    AlgorithmPolicy,
    FrozenStrictBaseModel,
    Key,
)

__author__ = "ft"


CryptographyPubKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class KSKM_PublicKey(FrozenStrictBaseModel, ABC):
    """Base class for parsed public keys."""

    bits: int
    algorithm: AlgorithmDNSSEC

    @classmethod
    def from_key(cls, key: Key) -> "KSKM_PublicKey":
        return KSKM_PublicKey.from_bytes(key.public_key, key.algorithm)

    @classmethod
    def from_bytes(
        cls, public_key: bytes, algorithm: AlgorithmDNSSEC
    ) -> "KSKM_PublicKey":
        from kskm.common.ecdsa_utils import KSKM_PublicKey_ECDSA, is_algorithm_ecdsa
        from kskm.common.rsa_utils import KSKM_PublicKey_RSA, is_algorithm_rsa

        if is_algorithm_rsa(algorithm):
            return KSKM_PublicKey_RSA.decode_public_key(public_key, algorithm)
        if is_algorithm_ecdsa(algorithm):
            return KSKM_PublicKey_ECDSA.decode_public_key(public_key, algorithm)
        raise RuntimeError(f"Can't make public key instance for algorithm {algorithm}")

    @abstractmethod
    def to_cryptography_pubkey(self) -> CryptographyPubKey:
        """Return a 'cryptography' public key object."""
        pass

    @abstractmethod
    def verify_signature(self, signature: bytes, data: bytes) -> None:
        """Verify a signature over 'data' using the 'cryptography' library."""
        pass

    @abstractmethod
    def to_algorithm_policy(self) -> AlgorithmPolicy:
        """Return an algorithm policy instance for this key."""
        pass

    @classmethod
    @abstractmethod
    def decode_public_key(cls, key: bytes, algorithm: AlgorithmDNSSEC) -> Self:
        """Decode a public key from a base64 string."""
        pass

    @abstractmethod
    def encode_public_key(self) -> bytes:
        """Encode the public key to a base64 string."""
        pass
