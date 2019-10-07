"""Data classes common to KSR and SKR Classes."""
from abc import ABC
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Set, TypeVar

# Type definitions to refer to the ABC types declared below
BundleType = TypeVar('BundleType', bound='Bundle')
AlgorithmPolicyType = TypeVar('AlgorithmPolicyType', bound='AlgorithmPolicy')


class AlgorithmDNSSEC(Enum):
    DSA = 3
    RSASHA1 = 5
    RSASHA256 = 8
    RSASHA512 = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16


class TypeDNSSEC(Enum):
    DNSKEY = 48


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
class AlgorithmPolicyECDSA(AlgorithmPolicy):
    pass


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


@dataclass(frozen=True)
class Signer(object):
    key_identifier: Optional[str]


@dataclass(frozen=True)
class Signature(object):
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


@dataclass(frozen=True)
class Key(object):
    key_identifier: str
    key_tag: int
    ttl: int
    flags: int
    protocol: int
    algorithm: AlgorithmDNSSEC
    public_key: bytes = field(repr=False)

    def __post_init__(self):
        """Check for valid DNSKEY flags."""
        if self.flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value or \
           self.flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value | FlagsDNSKEY.REVOKE.value or \
           self.flags == FlagsDNSKEY.ZONE.value:
            return
        raise ValueError(f"Unsupported DNSSEC key flags combination {self.flags}")


@dataclass(frozen=True)
class Bundle(ABC):
    id: str
    inception: datetime
    expiration: datetime
    keys: Set[Key]
    signatures: Set[Signature]
