"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC, abstractmethod
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicy, FrozenStrictBaseModel

__author__ = "ft"


CryptographyPubKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class KSKM_PublicKey(FrozenStrictBaseModel, ABC):
    """Base class for parsed public keys."""

    bits: int

    @abstractmethod
    def to_cryptography_pubkey(self) -> CryptographyPubKey:
        """Return a 'cryptography' public key object."""
        raise NotImplementedError(
            "to_cryptography_pubkey() must be implemented by subclasses."
        )

    @abstractmethod
    def verify_signature(
        self, signature: bytes, data: bytes, algorithm: AlgorithmDNSSEC
    ) -> None:
        """Verify a signature over 'data' using the 'cryptography' library."""
        raise NotImplementedError(
            "verify_signature() must be implemented by subclasses."
        )

    @abstractmethod
    def to_algorithm_policy(self, algorithm: AlgorithmDNSSEC) -> AlgorithmPolicy:
        """Return an algorithm policy instance for this key."""
        raise NotImplementedError(
            "to_algorithm_policy() must be implemented by subclasses.")

    @classmethod
    @abstractmethod
    def decode_public_key(cls, key: bytes, algorithm: AlgorithmDNSSEC) -> Self:
        """Decode a public key from a base64 string."""
        raise NotImplementedError(
            "decode_public_key() must be implemented by subclasses."
        )

    @abstractmethod
    def encode_public_key(self, algorithm: AlgorithmDNSSEC) -> bytes:
        """Encode the public key to a base64 string."""
        raise NotImplementedError(
            "encode_public_key() must be implemented by subclasses."
        )

def algorithm_to_hash(alg: AlgorithmDNSSEC) -> SHA256 | SHA384:
    if alg in [AlgorithmDNSSEC.RSASHA256, AlgorithmDNSSEC.ECDSAP256SHA256]:
        return SHA256()
    if alg in [AlgorithmDNSSEC.ECDSAP384SHA384]:
        return SHA384()
    raise ValueError(f"Hashing for algorithm {alg} not supported")
