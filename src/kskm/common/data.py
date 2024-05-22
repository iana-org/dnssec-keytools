"""Data classes common to KSR and SKR Classes."""

from abc import ABC
from base64 import b64decode
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

# Type definitions to refer to the ABC types declared below

BundleType = TypeVar("BundleType", bound="Bundle")
AlgorithmPolicyType = TypeVar("AlgorithmPolicyType", bound="AlgorithmPolicy")


class FrozenBaseModel(BaseModel, ABC):
    """
    A frozen abstract base class for Pydantic models.

    This variant allows coercion of data - used when loading configuration objects to e.g.
    get time deltas loaded transparently from strings.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


class FrozenStrictBaseModel(BaseModel, ABC):
    """
    A frozen *strict* abstract base class for Pydantic models.

    This variant does NOT allow coercion of data - used when loading KSRs/SKRs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


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


class AlgorithmPolicy(FrozenStrictBaseModel):
    """Algorithm Policy."""

    bits: int
    algorithm: AlgorithmDNSSEC


class AlgorithmPolicyRSA(AlgorithmPolicy):
    """Algorithm Policy for RSA signatures."""

    exponent: int


class AlgorithmPolicyECDSA(AlgorithmPolicy):
    """Algorithm Policy for ECDSA signatures."""


class AlgorithmPolicyDSA(AlgorithmPolicy):
    """Algorithm Policy for DSA signatures."""


class SignaturePolicy(FrozenStrictBaseModel):
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


class Signer(FrozenStrictBaseModel):
    """RRSIG Signer parameters."""

    if TYPE_CHECKING:
        # A frozen BaseModel will get a __hash__ function, but Pylance currently misses this
        def __hash__(self) -> int: ...

    key_identifier: str | None


class Signature(FrozenStrictBaseModel):
    """RRSIG parameters."""

    if TYPE_CHECKING:
        # A frozen BaseModel will get a __hash__ function, but Pylance currently misses this
        def __hash__(self) -> int: ...

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
    signature_data: bytes = Field(repr=False)

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return self.model_copy(update=kwargs)


class Key(FrozenStrictBaseModel):
    """DNSKEY parameters."""

    if TYPE_CHECKING:
        # A frozen BaseModel will get a __hash__ function, but Pylance currently misses this
        def __hash__(self) -> int: ...

    key_identifier: str
    key_tag: int
    ttl: int
    flags: int
    protocol: int
    algorithm: AlgorithmDNSSEC
    public_key: bytes = Field(repr=False)

    @field_validator("public_key", mode="after")
    @classmethod
    def ecdsa_public_key_size(cls, v: bytes, info: ValidationInfo) -> bytes:
        # have to import these locally to avoid circular imports  # noqa
        from kskm.common.ecdsa_utils import (
            ecdsa_public_key_without_prefix,
            expected_ecdsa_key_size,
            get_ecdsa_pubkey_size,
            is_algorithm_ecdsa,
        )

        _algorithm = info.data["algorithm"]
        if is_algorithm_ecdsa(_algorithm):
            _pubkey = ecdsa_public_key_without_prefix(b64decode(v), _algorithm)
            _size = get_ecdsa_pubkey_size(_pubkey)
            if _size != expected_ecdsa_key_size(_algorithm):
                raise ValueError(
                    f"Unexpected ECDSA key length {_size} for algorithm {_algorithm}"
                )
        return v

    @field_validator("flags", mode="after")
    @classmethod
    def validate_flags(cls, flags: int, info: ValidationInfo) -> int:
        if (
            flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
            or flags
            == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value | FlagsDNSKEY.REVOKE.value
            or flags == FlagsDNSKEY.ZONE.value
        ):
            return flags
        raise ValueError(f"Unsupported DNSSEC key flags combination {flags}")

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return self.model_copy(update=kwargs)


class Bundle(FrozenStrictBaseModel, ABC):
    """Request Bundle base class."""

    id: str
    inception: datetime
    expiration: datetime
    keys: set[Key]
    signatures: set[Signature]

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated."""
        return self.model_copy(update=kwargs)
