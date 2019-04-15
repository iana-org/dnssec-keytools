"""The checks defined in the 'Verify KSR header' section of docs/ksr-processing.md."""
from logging import Logger

from kskm.common.validate import PolicyViolation, fail
from kskm.ksr import Request
from kskm.common.config import RequestPolicy


class KSR_HeaderPolicyViolation(PolicyViolation):
    """Policy violation in a KSRs header."""

    pass


def verify_header(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Check the header elements of a Key Signing Request."""
    logger.debug('Begin "Verify KSR header"')

    check_domain(request, policy, logger)
    check_id(request, policy, logger)

    logger.debug('End "Verify KSR header"')


def check_domain(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check the domain name in the request.

    KSR-DOMAIN:
      Verify that the KSR domain name is correct.
    """
    if request.domain not in policy.acceptable_domains:
        fail(policy, KSR_HeaderPolicyViolation,
             f'KSR-DOMAIN: Request domain {request.domain!r} not in '
             f'policy\'s acceptable domains {policy.acceptable_domains}')
    else:
        logger.info(f'KSR-DOMAIN: Verified domain {request.domain!r}')


def check_id(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check the ID in the request.

    KSR-ID:
      Verify that the KSR ID is unique.
    """
    # TODO: Implement check of unique request ID.
    #       How is this best done? Provide path to directory with previous KSRs as argument,
    #       filename for last KSR as argument, or a small plain-text database with all IDs seen
    #       previously?
    logger.info('KSR-ID: Not implemented yet')
