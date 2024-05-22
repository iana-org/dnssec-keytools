"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC
from typing import Any, Self

from kskm.common.data import FrozenStrictBaseModel

__author__ = "ft"


class KSKM_PublicKey(FrozenStrictBaseModel, ABC):
    """Base class for parsed public keys."""

    bits: int

    def replace(self, **kwargs: Any) -> Self:
        """Return a new instance with the provided attributes updated."""
        return self.model_copy(update=kwargs)
