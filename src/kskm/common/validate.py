"""Common code and base exception classes used in KSR/SKR validation."""

import logging

__author__ = "ft"


logger = logging.getLogger(__name__)


class PolicyViolation(Exception):
    """Base class exception for all validation errors."""
