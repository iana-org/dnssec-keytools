"""Sub-parts of KSKMConfig (in config.py)."""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, NewType, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, FilePath, field_validator

from kskm.common.data import AlgorithmDNSSEC, SignaturePolicy
from kskm.common.parse_utils import duration_to_timedelta

__author__ = "ft"


PolicyType = TypeVar("PolicyType", bound="Policy")


class FrozenBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Policy(FrozenBaseModel, ABC):
    """Base class for RequestPolicy and ResponsePolicy."""

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        _data = self.model_dump()
        _data.update(kwargs)
        return self.model_validate(_data)


class RequestPolicy(Policy):
    """Configuration knobs for validating KSRs."""

    # Verify KSR header parameters
    acceptable_domains: list[str] = Field(default_factory=lambda: ["."])

    # Verify KSR bundles
    num_bundles: int = 9
    validate_signatures: bool = True
    keys_match_zsk_policy: bool = True
    rsa_exponent_match_zsk_policy: bool = True
    enable_unsupported_ecdsa: bool = False
    check_cycle_length: bool = True
    min_cycle_inception_length: timedelta = Field(
        default_factory=lambda: duration_to_timedelta("P79D")
    )
    max_cycle_inception_length: timedelta = Field(
        default_factory=lambda: duration_to_timedelta("P81D")
    )
    min_bundle_interval: timedelta = Field(
        default_factory=lambda: duration_to_timedelta("P9D")
    )
    max_bundle_interval: timedelta = Field(
        default_factory=lambda: duration_to_timedelta("P11D")
    )

    # Verify KSR policy parameters
    check_bundle_overlap: bool = True
    signature_algorithms_match_zsk_policy: bool = True
    approved_algorithms: list[str] = Field(
        default_factory=lambda: [AlgorithmDNSSEC.RSASHA256.name]
    )
    rsa_approved_exponents: list[int] = Field(default_factory=lambda: [65537])
    rsa_approved_key_sizes: list[int] = Field(default_factory=lambda: [2048])
    signature_validity_match_zsk_policy: bool = True
    check_keys_match_ksk_operator_policy: bool = True
    num_keys_per_bundle: list[int] = Field(
        default_factory=lambda: [2, 1, 1, 1, 1, 1, 1, 1, 2]
    )
    num_different_keys_in_all_bundles: int = 3
    dns_ttl: int = (
        0  # if this is 0, the config value ksk_policy.ttl will be used instead
    )
    signature_check_expire_horizon: bool = True
    signature_horizon_days: int = 180
    check_bundle_intervals: bool = True

    # Verify KSR/SKR chaining
    check_chain_keys: bool = True
    check_chain_keys_in_hsm: bool = True
    check_chain_overlap: bool = True
    check_keys_publish_safety: bool = True
    check_keys_retire_safety: bool = True


class ResponsePolicy(Policy):
    """Validation parameters for SKRs."""

    num_bundles: int = 9
    validate_signatures: bool = True


SigningKey = NewType("SigningKey", str)

SchemaName = NewType("SchemaName", str)


class SchemaAction(FrozenBaseModel):
    """Actions to take for a specific bundle."""

    publish: list[SigningKey]
    sign: list[SigningKey]
    revoke: list[SigningKey] = []

    @field_validator("*", mode="before")
    @classmethod
    def turn_into_string(cls, v: str | list[Any]) -> list[Any]:
        if isinstance(v, str):
            # Turn single strings into a list with one element
            return [v]
        return v


class Schema(FrozenBaseModel):
    """A named schema used when signing KSRs."""

    name: SchemaName
    actions: Mapping[int, SchemaAction]


class KSKPolicy(BaseModel):
    """
    Signing policy for the KSK operator.

    This corresponds to the 'ksk_policy' section of ksrsigner.yaml.

    Algorithms are not initialised here, but rather created dynamically from the KSK keys used
    in the schema.
    """

    signature_policy: SignaturePolicy = SignaturePolicy()
    ttl: int = 172800
    signers_name: str = "."


class KSKKey(BaseModel):
    """
    A key that can be used in schemas.

    This corresponds to an entry in the 'keys' section of ksrsigner.yaml.
    """

    description: str
    label: str
    key_tag: int | None
    algorithm: AlgorithmDNSSEC
    valid_from: datetime
    valid_until: datetime | None = None
    rsa_size: int | None = None
    rsa_exponent: int | None = None
    ds_sha256: str | None = None

    @field_validator("algorithm", mode="before")
    @classmethod
    def algorithm_by_name(cls, v: str | AlgorithmDNSSEC) -> AlgorithmDNSSEC:
        if isinstance(v, AlgorithmDNSSEC):
            return v
        try:
            return AlgorithmDNSSEC[v]
        except KeyError:
            raise ValueError("invalid algorithm")


class KSKMFilenames(BaseModel):
    """
    Filenames for various files.

    This corresponds to the 'filenames' section of ksrsigner.yaml.
    """

    previous_skr: FilePath | None = None
    input_ksr: FilePath | None = None
    output_skr: Path | None = None
    output_trustanchor: Path | None = None


class KSKMHSM(FrozenBaseModel):
    module: FilePath | str
    pin: str | int
    so_pin: str | int | None = None
    env: Mapping[str, Any] = Field(default_factory=dict)
