"""Common code and base exception classes used in KSR/SKR validation."""
import logging

from kskm.common.data import PolicyType

from typing import TypeVar, Type


__author__ = 'ft'


logger = logging.getLogger(__name__)


class PolicyViolation(Exception):
    """Base class exception for all validation errors."""

    pass


PolicyViolationType = TypeVar('PolicyViolationType', bound=PolicyViolation)


def fail(policy: PolicyType, exc: Type[PolicyViolationType], message: str) -> None:
    if policy.warn_instead_of_fail:
        logger.warning(message)
    else:
        raise exc(message)


