"""Data classes common to KSR and SKR Classes."""

from abc import ABC
from base64 import b64decode
from dataclasses import dataclass, field
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field

# Type definitions to refer to the ABC types declared below

BundleType = TypeVar("BundleType", bound="Bundle")
AlgorithmPolicyType = TypeVar("AlgorithmPolicyType", bound="AlgorithmPolicy")


class FrozenBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AlgorithmDNSSEC(Enum):
    """
    DNSSEC Algorithms.

    https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    """

    RSAMD5 = 1
    DSA = 3
    RSASHA1 = 5
    DSA_NSEC3_SHA1 = 6
    RSASHA1_NSEC3_SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECC_GOST = 12
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16


# Algorithms listed as MUST NOT implement in RFC 8624
DEPRECATED_ALGORITHMS = [
    AlgorithmDNSSEC.RSAMD5,
    AlgorithmDNSSEC.DSA,
    AlgorithmDNSSEC.DSA_NSEC3_SHA1,
    AlgorithmDNSSEC.ECC_GOST,
]

# Supported algorithms (note that ECDSA is not yet fully supported)
SUPPORTED_ALGORITHMS = [
    AlgorithmDNSSEC.RSASHA256,
    AlgorithmDNSSEC.RSASHA512,
    AlgorithmDNSSEC.ECDSAP256SHA256,
    AlgorithmDNSSEC.ECDSAP384SHA384,
]


class TypeDNSSEC(Enum):
    """DNS RR type."""

    DNSKEY = 48


class FlagsDNSKEY(Enum):
    """DNSKEY flags."""

    SEP = 0x0001
    REVOKE = 0x0080
    ZONE = 0x0100


@dataclass(frozen=True)
class AlgorithmPolicy:
    """Algorithm Policy."""

    bits: int
    algorithm: AlgorithmDNSSEC


@dataclass(frozen=True)
class AlgorithmPolicyRSA(AlgorithmPolicy):
    """Algorithm Policy for RSA signatures."""

    exponent: int


@dataclass(frozen=True)
class AlgorithmPolicyECDSA(AlgorithmPolicy):
    """Algorithm Policy for ECDSA signatures."""


@dataclass(frozen=True)
class AlgorithmPolicyDSA(AlgorithmPolicy):
    """Algorithm Policy for DSA signatures."""


class SignaturePolicy(FrozenBaseModel):
    """DNSSEC Signature Policy."""

    publish_safety: timedelta = Field(default=timedelta())
    retire_safety: timedelta = Field(default=timedelta())
    max_signature_validity: timedelta = Field(default=timedelta())
    min_signature_validity: timedelta = Field(default=timedelta())
    max_validity_overlap: timedelta = Field(default=timedelta())
    min_validity_overlap: timedelta = Field(default=timedelta())
    algorithms: set[AlgorithmPolicy] = Field(default_factory=set)

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return self.model_copy(update=kwargs)


@dataclass(frozen=True)
class Signer:
    """RRSIG Signer parameters."""

    key_identifier: str | None


@dataclass(frozen=True)
class Signature:
    """RRSIG parameters."""

    key_identifier: str
    ttl: int
    type_covered: TypeDNSSEC
    algorithm: AlgorithmDNSSEC
    labels: int
    original_ttl: int
    signature_expiration: datetime
    signature_inception: datetime
    key_tag: int
    signers_name: str
    signature_data: bytes = field(repr=False)

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return dc_replace(self, **kwargs)


@dataclass(frozen=True)
class Key:
    """DNSKEY parameters."""

    key_identifier: str
    key_tag: int
    ttl: int
    flags: int
    protocol: int
    algorithm: AlgorithmDNSSEC
    public_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Check for valid DNSKEY flags."""
        # have to import these locally to avoid circular imports  # noqa
        from kskm.common.ecdsa_utils import (
            ecdsa_public_key_without_prefix,
            expected_ecdsa_key_size,
            get_ecdsa_pubkey_size,
            is_algorithm_ecdsa,
        )

        if is_algorithm_ecdsa(self.algorithm):
            _pubkey = ecdsa_public_key_without_prefix(
                b64decode(self.public_key), self.algorithm
            )
            _size = get_ecdsa_pubkey_size(_pubkey)
            if _size != expected_ecdsa_key_size(self.algorithm):
                raise ValueError(
                    f"Unexpected ECDSA key length {_size} for algorithm {self.algorithm}"
                )

        if (
            self.flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
            or self.flags
            == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value | FlagsDNSKEY.REVOKE.value
            or self.flags == FlagsDNSKEY.ZONE.value
        ):
            return
        raise ValueError(f"Unsupported DNSSEC key flags combination {self.flags}")

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return dc_replace(self, **kwargs)


@dataclass(frozen=True)
class Bundle(ABC):
    """Request Bundle base class."""

    id: str
    inception: datetime
    expiration: datetime
    keys: set[Key]
    signatures: set[Signature]

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated."""
        return dc_replace(self, **kwargs)
