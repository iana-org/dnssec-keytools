"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC

from kskm.common.data import FrozenStrictBaseModel

__author__ = "ft"


class KSKM_PublicKey(FrozenStrictBaseModel, ABC):
    """Base class for parsed public keys."""

    bits: int
