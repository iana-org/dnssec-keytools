"""Code using the Cryptography library."""

import logging
from typing import Self

from pydantic import BaseModel

from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicy, Key
from kskm.common.ecdsa_utils import (
    algorithm_to_curve,
    decode_ecdsa_public_key,
    is_algorithm_ecdsa,
)
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import decode_rsa_public_key, is_algorithm_rsa

__author__ = "ft"

logger = logging.getLogger(__name__)


class CryptoPubKey(BaseModel):
    algorithm: AlgorithmDNSSEC
    public_key: KSKM_PublicKey

    @classmethod
    def from_key(cls, key: Key) -> Self:
        if is_algorithm_rsa(key.algorithm):
            return cls(
                algorithm=key.algorithm,
                public_key=decode_rsa_public_key(key.public_key),
            )
        if is_algorithm_ecdsa(key.algorithm):
            crv = algorithm_to_curve(key.algorithm)
            return cls(
                algorithm=key.algorithm,
                public_key=decode_ecdsa_public_key(key.public_key, crv),
            )
        raise RuntimeError(f"Can't make public key instance from {key}")

    def verify_signature(self, signature: bytes, data: bytes) -> None:
        """Verify a signature over 'data' using an 'cryptography' public key."""
        self.public_key.verify_signature(signature, data, self.algorithm)

    def to_algorithm_policy(self) -> AlgorithmPolicy:
        """Return an algorithm policy instance for this key."""
        return self.public_key.to_algorithm_policy(self.algorithm)
