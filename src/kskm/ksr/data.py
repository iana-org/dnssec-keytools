"""KSR (Request) data classes."""

from abc import ABC
from datetime import datetime
from typing import Any, Self

from kskm.common.data import Bundle, FrozenStrictBaseModel, SignaturePolicy, Signer


class RequestBundle(Bundle):
    """Request Bundle."""

    signers: set[Signer] | None


class KSR(FrozenStrictBaseModel, ABC):
    """KSR Base Class."""

    id: str
    serial: int
    domain: str
    timestamp: datetime | None

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated. Used in tests."""
        return self.model_copy(update=kwargs)


class Request(KSR):
    """Key Signing Request."""

    zsk_policy: SignaturePolicy
    # 'bundles' is supposed to be a Set, but a set cannot contain other sets
    # (TypeError: unhashable type: 'set')
    bundles: list[RequestBundle]

    xml_filename: str | None = None
    xml_hash: bytes | None = None
