"""Common code and base exception classes used in KSR/SKR validation."""
import logging
from typing import Type, TypeVar

from kskm.common.data import PolicyType

__author__ = 'ft'


logger = logging.getLogger(__name__)


class PolicyViolation(Exception):
    """Base class exception for all validation errors."""

    pass


PolicyViolationType = TypeVar('PolicyViolationType', bound=PolicyViolation)


def fail(policy: PolicyType, exc: Type[PolicyViolationType], message: str) -> None:
    """
    Raise an exception, or just log a warning if policy says warn_instead_of_fail.

    TODO: Should probably remove the warn_instead_of_fail mode. It should be sufficient
          to disable checks in the policy being used.
    """
    if policy.warn_instead_of_fail:
        logger.warning(message)
    else:
        raise exc(message)
