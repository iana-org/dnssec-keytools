"""A module to hold the shared base class for KSKM public keys."""

from abc import ABC
from dataclasses import dataclass
from typing import TypeVar

__author__ = 'ft'


KSKM_PublicKeyType = TypeVar('KSKM_PublicKeyType', bound='KSKM_PublicKey')


@dataclass(frozen=True)
class KSKM_PublicKey(ABC):
    """Base class for parsed public keys."""

    bits: int
