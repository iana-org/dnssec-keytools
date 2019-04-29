"""The checks defined in the 'Verify KSR header' section of docs/ksr-processing.md."""
from logging import Logger

from kskm.common.validate import PolicyViolation, fail
from kskm.ksr import Request
from kskm.common.config_misc import RequestPolicy


class KSR_HeaderPolicyViolation(PolicyViolation):
    """Policy violation in a KSRs header."""

    pass


class KSR_ID_Violation(KSR_HeaderPolicyViolation):
    """KSR-ID policy violation"""

    pass


def verify_header(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """Check the header elements of a Key Signing Request."""
    logger.debug('Begin "Verify KSR header"')

    check_domain(request, policy, logger)
    check_id(request, policy, logger)
    check_serial(request, policy, logger)

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
    logger.info('KSR-ID: Will be checked later, when SKR is available')


def check_serial(request: Request, policy: RequestPolicy, logger: Logger) -> None:
    """
    Check the serial in the request.

    KSR-SERIAL:
      Verify that the KSR SERIAL is unique and incresing for the the KSR ID.
    """
    # TODO: Implement check of unique request SERAIL.
    logger.info('KSR-SERIAL: Not implemented yet')
