"""KSR (Request) data classes."""
from abc import ABC
from dataclasses import dataclass
from typing import List, Optional, Set

from kskm.common.data import SignaturePolicy, Bundle, Signer


@dataclass(frozen=True)
class RequestBundle(Bundle):
    signers: Optional[Set[Signer]]


@dataclass(frozen=True)
class KSR(ABC):
    id: str
    serial: int
    domain: str
    # TODO: The example KSR does not have a timestamp, and I don't see it in the schema (ksr.rnc)
    # timestamp: datetime


@dataclass(frozen=True)
class Request(KSR):
    zsk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: List[RequestBundle]
