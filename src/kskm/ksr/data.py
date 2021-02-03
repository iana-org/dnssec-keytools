"""KSR (Request) data classes."""
from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set

from kskm.common.data import Bundle, SignaturePolicy, Signer


@dataclass(frozen=True)
class RequestBundle(Bundle):
    """Request Bundle."""

    signers: Optional[Set[Signer]]


@dataclass(frozen=True)
class KSR(ABC):
    """KSR Base Class."""

    id: str
    serial: int
    domain: str
    timestamp: Optional[datetime]


@dataclass(frozen=True)
class Request(KSR):
    """Key Signing Request."""

    zsk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: List[RequestBundle]

    xml_filename: Optional[str] = None
    xml_hash: Optional[bytes] = None
