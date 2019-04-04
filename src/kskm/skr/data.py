"""SKR (Response) data classes."""
from dataclasses import dataclass
from typing import List
from abc import ABC

from kskm.common.data import Bundle, SignaturePolicy


@dataclass(frozen=True)
class ResponseBundle(Bundle):
    pass


@dataclass(frozen=True)
class SKR(ABC):
    id: str
    serial: int
    domain: str
    # TODO: The example KSR does not have a timestamp, and I don't see it in the schema (ksr.rnc)
    # timestamp: datetime


@dataclass(frozen=True)
class Response(SKR):
    zsk_policy: SignaturePolicy
    ksk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: List[ResponseBundle]
