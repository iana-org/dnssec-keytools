"""Functions to validate SKRs."""
import logging

from kskm.common.validate import PolicyViolation, fail
from kskm.skr.data import Response, ResponseBundle
from kskm.skr.policy import ResponsePolicy

from kskm.common.signature import validate_signatures, InvalidSignature


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
        fail(policy, PolicyViolation, 'Wrong number of bundles in response ({}, expected {})'.format(
            len(response.bundles), policy.num_bundles))
    for bundle in response.bundles:
        # check that all keys in the bundle are covered by a correct signature
        check_valid_signatures(bundle, policy)
    return True


def check_valid_signatures(bundle: ResponseBundle, policy: ResponsePolicy) -> None:
    """Validate requester proof of ownership of all the keys in the bundles."""
    if not policy.validate_signatures:
        return
    try:
        if not validate_signatures(bundle):
            fail(policy, InvalidSignatureViolation,
                 'Unknown signature validation result in bundle {}'.format(bundle.id))
    except InvalidSignature:
        fail(policy, InvalidSignatureViolation,
             'Invalid signature encountered in bundle {}'.format(bundle.id))
