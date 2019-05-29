"""Functions to validate SKRs."""
import logging

from kskm.common.config_misc import ResponsePolicy
from kskm.common.signature import InvalidSignature, validate_signatures
from kskm.common.validate import PolicyViolation
from kskm.skr.data import Response, ResponseBundle

__author__ = 'ft'


logger = logging.getLogger(__name__)


class InvalidSignatureViolation(PolicyViolation):
    """Exception raised when a signature fails validation."""

    pass


def validate_response(response: Response, policy: ResponsePolicy) -> bool:
    """
    Validate that a loaded response conforms to the policy.

    All the sub-functions to this function are expected to raise a PolicyException
    on errors. Dealing with return values to determine outcome makes it too easy
    to screw up.
    """
    if policy.num_bundles is not None and len(response.bundles) != policy.num_bundles:
        raise PolicyViolation(f'Wrong number of bundles in response ({len(response.bundles)}, '
                              f'expected {policy.num_bundles})')
    for bundle in response.bundles:
        # check that all keys in the bundle are covered by a correct signature
        check_valid_signatures(bundle, policy)
    return True


def check_valid_signatures(bundle: ResponseBundle, policy: ResponsePolicy) -> None:
    """Validate requester proof of ownership of all the keys in the bundles."""
    if not policy.validate_signatures:
        # TODO: Describe checking of produced signatures (and signatures from SKR(n-1) in ksr-processsing.md
        logger.warning('SKR signature validation disabled by policy (validate_signatures)')
        return
    try:
        if not validate_signatures(bundle):
            raise InvalidSignatureViolation(f'Unknown signature validation result in bundle {bundle.id}')
    except InvalidSignature:
        raise InvalidSignatureViolation(f'Invalid signature encountered in bundle {bundle.id}')
