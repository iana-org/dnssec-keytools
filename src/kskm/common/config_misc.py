"""Sub-parts of KSKMConfig (in config.py)."""

from abc import ABC
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, NewType, Self, TypeVar

from pydantic import Field, FilePath, PositiveInt, StringConstraints, field_validator

from kskm.common.data import AlgorithmDNSSEC, FrozenBaseModel, SignaturePolicy
from kskm.common.parse_utils import duration_to_timedelta

__author__ = "ft"


DomainNameString = Annotated[str, StringConstraints(pattern=r"^[\w\.]+$")]
IntegerRSASize = Annotated[int, Field(ge=1, le=65535)]
IntegerDNSTTL = Annotated[int, Field(ge=0)]
HexDigestString = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]+$")]


PolicyType = TypeVar("PolicyType", bound="Policy")


class Policy(FrozenBaseModel, ABC):
    """Base class for RequestPolicy and ResponsePolicy."""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Instantiate the policy from a dict of values."""
        _data = deepcopy(dict(data))  # don't mess with caller's data
        # Convert durations provided as strings into datetime.timedelta instances
        for this_td in [
            "min_bundle_interval",
            "max_bundle_interval",
            "min_cycle_inception_length",
            "max_cycle_inception_length",
        ]:
            if this_td in _data:
                _data[this_td] = duration_to_timedelta(data[this_td])
        return cls.model_validate(_data)

    def to_dict(self) -> dict[str, Any]:
        """Convert the policy to a dictionary."""
        return self.model_dump()


class RequestPolicy(Policy):
    """Configuration knobs for validating KSRs."""

    # Verify KSR header parameters
    acceptable_domains: list[DomainNameString] = Field(default_factory=lambda: ["."])

    # Verify KSR bundles
    num_bundles: int = 9  # can be 0 in tests, but will be enforced ge=1 upon load
    validate_signatures: bool = True
    keys_match_zsk_policy: bool = True
    rsa_exponent_match_zsk_policy: bool = True
    enable_unsupported_ecdsa: bool = False
    enable_unsupported_edwards_dsa: bool = False
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
    rsa_approved_exponents: list[PositiveInt] = Field(default_factory=lambda: [65537])
    rsa_approved_key_sizes: list[IntegerRSASize] = Field(default_factory=lambda: [2048])
    signature_validity_match_zsk_policy: bool = True
    check_keys_match_ksk_operator_policy: bool = True
    num_keys_per_bundle: list[PositiveInt] = Field(
        default_factory=lambda: [2, 1, 1, 1, 1, 1, 1, 1, 2]
    )
    num_different_keys_in_all_bundles: int = (
        3  # can be 0 in tests, but will be enforced ge=1 upon load
    )
    dns_ttl: IntegerDNSTTL = (
        0  # if this is 0, the config value ksk_policy.ttl will be used instead
    )
    signature_check_expire_horizon: bool = True
    signature_horizon_days: int = (
        180  # can be negative in tests, but will be enforced positive on config load
    )
    check_bundle_intervals: bool = True

    # Verify KSR/SKR chaining
    check_chain_keys: bool = True
    check_chain_keys_in_hsm: bool = True
    check_chain_overlap: bool = True
    check_keys_publish_safety: bool = True
    check_keys_retire_safety: bool = True


class ResponsePolicy(Policy):
    """Validation parameters for SKRs."""

    num_bundles: PositiveInt = 9
    validate_signatures: bool = True


KeyName = Annotated[str, StringConstraints(pattern=r"^[\w_]+$")]

SchemaName = NewType("SchemaName", str)


class SchemaAction(FrozenBaseModel):
    """Actions to take for a specific bundle."""

    publish: list[KeyName]
    sign: list[KeyName]
    revoke: list[KeyName] = []

    @field_validator("*", mode="before")
    @classmethod
    def turn_into_list(cls, v: str | list[Any]) -> list[Any]:
        if isinstance(v, str):
            # Turn single strings into a list with one element
            return [v]
        return v


class Schema(FrozenBaseModel):
    """A named schema used when signing KSRs."""

    name: SchemaName
    actions: Mapping[int, SchemaAction]


class KSKPolicy(FrozenBaseModel):
    """
    Signing policy for the KSK operator.

    This corresponds to the 'ksk_policy' section of ksrsigner.yaml.

    Algorithms are not initialised here, but rather created dynamically from the KSK keys used
    in the schema.
    """

    signature_policy: SignaturePolicy = Field(default_factory=SignaturePolicy)
    ttl: IntegerDNSTTL = 172800
    signers_name: DomainNameString = "."


class KSKKey(FrozenBaseModel):
    """
    A key that can be used in schemas.

    This corresponds to an entry in the 'keys' section of ksrsigner.yaml.
    """

    description: str
    label: KeyName
    key_tag: int | None = Field(default=None, ge=1, le=65535)
    algorithm: AlgorithmDNSSEC
    valid_from: datetime
    valid_until: datetime | None = None
    rsa_size: IntegerRSASize | None = None
    rsa_exponent: PositiveInt | None = None
    ds_sha256: HexDigestString | None = None
    hash_using_hsm: bool | None = None

    @field_validator("algorithm", mode="before")
    @classmethod
    def algorithm_by_name(cls, v: str | AlgorithmDNSSEC) -> AlgorithmDNSSEC:
        if isinstance(v, AlgorithmDNSSEC):
            return v
        try:
            return AlgorithmDNSSEC[v]
        except KeyError as err:
            raise ValueError("invalid algorithm") from err


class KSKMFilenames(FrozenBaseModel):
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
    pin: str | int | None = None
    so_pin: str | int | None = None
    env: Mapping[str, Any] = Field(default_factory=dict)
