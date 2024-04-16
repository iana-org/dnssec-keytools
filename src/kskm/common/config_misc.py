"""Sub-parts of KSKMConfig (in config.py)."""

from __future__ import annotations

from abc import ABC
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, NewType, TypeVar

from pydantic import BaseModel

from kskm.common.data import AlgorithmDNSSEC, SignaturePolicy
from kskm.common.parse_utils import duration_to_timedelta, parse_datetime

__author__ = "ft"


PolicyType = TypeVar("PolicyType", bound="Policy")
KSKKeysType = NewType("KSKKeysType", Mapping[str, "KSKKey"])


@dataclass(frozen=True)
class Policy(ABC):
    """Base class for RequestPolicy and ResponsePolicy."""

    # avoid upsetting type checker in from_dict below when arguments are passed to cls() without any attributes
    _dataclass_placeholder: bool | None = None

    @classmethod
    def from_dict(cls: type[PolicyType], data: dict[str, Any]) -> PolicyType:
        """Instantiate ResponsePolicy from a dict of values."""
        _data = deepcopy(data)  # don't mess with caller's data
        # Convert durations provided as strings into datetime.timedelta instances
        for this_td in [
            "min_bundle_interval",
            "max_bundle_interval",
            "min_cycle_inception_length",
            "max_cycle_inception_length",
        ]:
            if this_td in _data:
                _data[this_td] = duration_to_timedelta(data[this_td])
        return cls(**_data)


@dataclass(frozen=True)
class RequestPolicy(Policy):
    """Configuration knobs for validating KSRs."""

    # Verify KSR header parameters
    acceptable_domains: list[str] = field(default_factory=lambda: ["."])

    # Verify KSR bundles
    num_bundles: int = 9
    validate_signatures: bool = True
    keys_match_zsk_policy: bool = True
    rsa_exponent_match_zsk_policy: bool = True
    enable_unsupported_ecdsa: bool = False
    check_cycle_length: bool = True
    min_cycle_inception_length: timedelta = field(
        default_factory=lambda: duration_to_timedelta("P79D")
    )
    max_cycle_inception_length: timedelta = field(
        default_factory=lambda: duration_to_timedelta("P81D")
    )
    min_bundle_interval: timedelta = field(
        default_factory=lambda: duration_to_timedelta("P9D")
    )
    max_bundle_interval: timedelta = field(
        default_factory=lambda: duration_to_timedelta("P11D")
    )

    # Verify KSR policy parameters
    check_bundle_overlap: bool = True
    signature_algorithms_match_zsk_policy: bool = True
    approved_algorithms: list[str] = field(
        default_factory=lambda: [AlgorithmDNSSEC.RSASHA256.name]
    )
    rsa_approved_exponents: list[int] = field(default_factory=lambda: [65537])
    rsa_approved_key_sizes: list[int] = field(default_factory=lambda: [2048])
    signature_validity_match_zsk_policy: bool = True
    check_keys_match_ksk_operator_policy: bool = True
    num_keys_per_bundle: list[int] = field(
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


@dataclass(frozen=True)
class ResponsePolicy(Policy):
    """Validation parameters for SKRs."""

    num_bundles: int = 9
    validate_signatures: bool = True


SigningKey = NewType("SigningKey", str)


@dataclass(frozen=True)
class SchemaAction:
    """Actions to take for a specific bundle."""

    publish: Iterable[SigningKey]
    sign: Iterable[SigningKey]
    revoke: Iterable[SigningKey]


@dataclass(frozen=True)
class Schema:
    """A named schema used when signing KSRs."""

    name: str
    actions: Mapping[int, SchemaAction]


def parse_keylist(elem: str | list[str]) -> list[SigningKey]:
    if isinstance(elem, list):
        return [SigningKey(x) for x in elem]
    return [SigningKey(elem)]


class KSKPolicy(BaseModel):
    """
    Signing policy for the KSK operator.

    This corresponds to the 'ksk_policy' section of ksrsigner.yaml.

    Algorithms are not initialised here, but rather created dynamically from the KSK keys used
    in the schema.
    """

    signature_policy: SignaturePolicy
    ttl: int = 172800
    signers_name: str = "."


@dataclass()
class KSKKey:
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

    @classmethod
    def from_dict(cls: type[KSKKey], data: dict[str, Any]) -> KSKKey:
        """Instantiate KSKKey from a dict of values."""
        # do not modify callers data
        _data = deepcopy(data)
        if "algorithm" in _data:
            _data["algorithm"] = AlgorithmDNSSEC[_data["algorithm"]]
        for _dt in ["valid_from", "valid_until"]:
            # If the dict is loaded from YAML, these values will already be converted to datetime.
            # If they are not, convert them here.
            if _dt in _data and not isinstance(_data[_dt], datetime):
                _data[_dt] = parse_datetime(_data[_dt])
            elif _dt in _data:
                # Set timezone UTC in the datetime
                _data[_dt] = _data[_dt].replace(tzinfo=timezone.utc)
        return cls(**_data)
