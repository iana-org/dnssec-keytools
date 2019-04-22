"""Sub-parts of KSKMConfig (in config.py)."""
from __future__ import annotations

from abc import ABC
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Mapping, NewType, Optional, Type, TypeVar, Union

from kskm.common.data import AlgorithmDNSSEC, SignaturePolicy
from kskm.common.parse_utils import duration_to_timedelta, parse_datetime

__author__ = 'ft'


PolicyType = TypeVar('PolicyType', bound='Policy')
KSKKeysType = NewType('KSKKeysType', Mapping[str, 'KSKKey'])


@dataclass(frozen=True)
class Policy(ABC):
    """Base class for RequestPolicy and ResponsePolicy."""

    warn_instead_of_fail: bool = False

    @classmethod
    def from_dict(cls: Type[PolicyType], data: dict) -> PolicyType:
        """Instantiate ResponsePolicy from a dict of values."""
        return cls(**data)


@dataclass(frozen=True)
class RequestPolicy(Policy):
    """Configuration knobs for validating KSRs."""

    # Verify KSR header parameters
    acceptable_domains: List[str] = field(default_factory=lambda: ['.'])

    # Verify KSR bundles
    num_bundles: int = 9
    validate_signatures: bool = True
    keys_match_zsk_policy: bool = True
    rsa_exponent_match_zsk_policy: bool = True

    # Verify KSR policy parameters
    check_bundle_overlap: bool = True
    signature_algorithms_match_zsk_policy: bool = True
    approved_algorithms: List[str] = field(default_factory=lambda: ['RSASHA256'])
    rsa_approved_exponents: List[int] = field(default_factory=lambda: [3, 65537])
    rsa_approved_key_sizes: List[int] = field(default_factory=lambda: [2048])
    signature_validity_match_zsk_policy: bool = True
    check_keys_match_ksk_operator_policy: bool = True
    # TODO: Only have 3 as acceptable key set length, and require special policy for special case?
    acceptable_key_set_lengths: List[int] = field(default_factory=lambda: [2, 3])
    dns_ttl: int = 0  # if this is 0, the config value ksk_policy.ttl will be used instead

    # Verify KSR/SKR chaining
    check_request_daisy_chain: bool = True
    # TODO: match policy timers
    # TODO: match policy algorithms (match against acceptable)
    # TODO: protocol, flags match
    # TODO: TTL limit


@dataclass(frozen=True)
class ResponsePolicy(Policy):
    """Validation parameters for SKRs."""

    num_bundles: int = 9
    validate_signatures: bool = True


SigningKey = NewType('SigningKey', str)


@dataclass(frozen=True)
class SchemaAction(object):
    """Actions to take for a specific bundle."""

    publish: Iterable[SigningKey]
    sign: Iterable[SigningKey]
    revoke: Iterable[SigningKey]


@dataclass(frozen=True)
class Schema(object):
    """A named schema used when signing KSRs."""

    name: str
    actions: Mapping[int, SchemaAction]


def _parse_keylist(elem: Union[str, List[str]]) -> List[SigningKey]:
    if isinstance(elem, list):
        return [SigningKey(x) for x in elem]
    return [SigningKey(elem)]


@dataclass()
class KSKPolicy(object):
    """
    Signing policy for the KSK operator.

    This corresponds to the 'ksk_policy' section of ksrsigner.yaml.
    """

    signature_policy: SignaturePolicy
    ttl: int
    signers_name: str = '.'

    @classmethod
    def from_dict(cls, data: Mapping) -> KSKPolicy:
        """
        Load the 'ksk_policy' section of the configuration.

        Algorithms are not initialised here, but rather created dynamically from the KSK keys used
        in the schema.
        """
        def _get_timedelta(name: str) -> timedelta:
            return duration_to_timedelta(data.get(name))

        _sp = SignaturePolicy(publish_safety=_get_timedelta('publish_safety'),
                              retire_safety=_get_timedelta('retire_safety'),
                              max_signature_validity=_get_timedelta('max_signature_validity'),
                              min_signature_validity=_get_timedelta('min_signature_validity'),
                              max_validity_overlap=_get_timedelta('max_validity_overlap'),
                              min_validity_overlap=_get_timedelta('min_validity_overlap'),
                              algorithms=set(),
                              )
        return cls(signature_policy=_sp,
                   ttl=int(data.get('ttl', 172800)),
                   )


@dataclass()
class KSKKey(object):
    """
    A key that can be used in schemas.

    This corresponds to an entry in the 'keys' section of ksrsigner.yaml.
    """

    description: str
    label: str
    algorithm: AlgorithmDNSSEC
    valid_from: datetime
    valid_until: Optional[datetime] = None
    rsa_size: Optional[int] = None
    rsa_exponent: Optional[int] = None

    @classmethod
    def from_dict(cls: Type[KSKKey], data: dict) -> KSKKey:
        """Instantiate KSKKey from a dict of values."""
        # do not modify callers data
        _data = deepcopy(data)
        if 'algorithm' in _data:
            _data['algorithm'] = AlgorithmDNSSEC[_data['algorithm']]
        for _dt in ['valid_from', 'valid_until']:
            # If the dict is loaded from YAML, these values will already be converted to datetime.
            # If they are not, convert them here.
            if _dt in _data and not isinstance(_data[_dt], datetime):
                _data[_dt] = parse_datetime(_data[_dt])
            elif _dt in _data:
                # Set timezone UTC in the datetime
                _data[_dt] = _data[_dt].replace(tzinfo=timezone.utc)
        return cls(**_data)
