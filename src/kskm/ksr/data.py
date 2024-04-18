"""KSR (Request) data classes."""

import dataclasses
from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self

from kskm.common.data import Bundle, SignaturePolicy, Signer


@dataclass(frozen=True)
class RequestBundle(Bundle):
    """Request Bundle."""

    signers: set[Signer] | None


@dataclass(frozen=True)
class KSR(ABC):
    """KSR Base Class."""

    id: str
    serial: int
    domain: str
    timestamp: datetime | None

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return dataclasses.replace(self, **kwargs)


@dataclass(frozen=True)
class Request(KSR):
    """Key Signing Request."""

    zsk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: list[RequestBundle]

    xml_filename: str | None = None
    xml_hash: bytes | None = None
