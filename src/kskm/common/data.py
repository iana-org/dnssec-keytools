"""Data classes common to KSR and SKR Classes."""
from abc import ABC
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Set, Optional, TypeVar, Type


# Type definitions to refer to the ABC types declared below
PolicyType = TypeVar('PolicyType', bound='Policy')
BundleType = TypeVar('BundleType', bound='Bundle')
AlgorithmPolicyType = TypeVar('AlgorithmPolicyType', bound='AlgorithmPolicy')


# TODO: use https://github.com/rthalley/dnspython/blob/master/dns/dnssec.py if we use it elsewhere
class AlgorithmDNSSEC(Enum):
    RSASHA1 = 5
    RSASHA256 = 8
    RSASHA512 = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16


# TODO: use https://github.com/rthalley/dnspython/blob/master/dns/rdatatype.py if we use it elsewhere
class TypeDNSSEC(Enum):
    DNSKEY = 48


# TODO: use https://github.com/rthalley/dnspython/blob/master/dns/rdtypes/dnskeybase.py if we use it elsewhere
class FlagsDNSKEY(Enum):
    SEP = 0x0001
    REVOKE = 0x0080
    ZONE = 0x0100


@dataclass(frozen=True)
class AlgorithmPolicy(object):
    bits: int
    algorithm: AlgorithmDNSSEC


@dataclass(frozen=True)
class AlgorithmPolicyRSA(AlgorithmPolicy):
    exponent: int


@dataclass(frozen=True)
class AlgorithmPolicyDSA(AlgorithmPolicy):
    pass


@dataclass(frozen=True)
class SignaturePolicy(object):
    publish_safety: timedelta
    retire_safety: timedelta
    max_signature_validity: timedelta
    min_signature_validity: timedelta
    max_validity_overlap: timedelta
    min_validity_overlap: timedelta
    algorithms: Set[AlgorithmPolicy]


# TODO: I believe this class is unused/used incorrectly
@dataclass(frozen=True)
class Signer(object):
    key_identifier: Optional[str]


@dataclass(frozen=True)
class Signature(object):
    key_identifier: Optional[str]
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


@dataclass(frozen=True)
class Key(object):
    key_identifier: Optional[str]  # TODO: Some checks compare keys using the identifier, won't work if it is None
    key_tag: int
    ttl: int
    flags: int
    protocol: int
    algorithm: AlgorithmDNSSEC
    public_key: bytes = field(repr=False)


@dataclass(frozen=True)
class Bundle(ABC):
    id: str
    inception: datetime
    expiration: datetime
    keys: Set[Key]
    signatures: Set[Signature]


@dataclass(frozen=True)
class Policy(ABC):
    """Base class for RequestPolicy and ResponsePolicy."""

    warn_instead_of_fail: bool = False

    @classmethod
    def from_dict(cls: Type[PolicyType], data: dict) -> PolicyType:
        """Instantiate ResponsePolicy from a dict of values."""
        return cls(**data)
