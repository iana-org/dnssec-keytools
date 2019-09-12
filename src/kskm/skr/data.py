"""SKR (Response) data classes."""
from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from kskm.common.data import Bundle, SignaturePolicy


@dataclass(frozen=True)
class ResponseBundle(Bundle):
    pass


@dataclass(frozen=True)
class SKR(ABC):
    id: str
    serial: int
    domain: str
    timestamp: Optional[datetime]


@dataclass(frozen=True)
class Response(SKR):
    zsk_policy: SignaturePolicy
    ksk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: List[ResponseBundle]
