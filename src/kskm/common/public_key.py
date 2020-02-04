"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC
from dataclasses import dataclass

__author__ = "ft"


@dataclass(frozen=True)
class KSKM_PublicKey(ABC):
    """Base class for parsed public keys."""

    bits: int
