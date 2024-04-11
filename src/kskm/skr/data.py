"""SKR (Response) data classes."""

from abc import ABC
from dataclasses import dataclass
from datetime import datetime

from kskm.common.data import Bundle, SignaturePolicy


@dataclass(frozen=True)
class ResponseBundle(Bundle):
    """Response Bundle."""


@dataclass(frozen=True)
class SKR(ABC):
    """Signed Key Response (SKR)."""

    id: str
    serial: int
    domain: str
    timestamp: datetime | None


@dataclass(frozen=True)
class Response(SKR):
    """SKR Response."""

    zsk_policy: SignaturePolicy
    ksk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: list[ResponseBundle]
