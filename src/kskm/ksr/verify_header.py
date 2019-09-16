"""The checks defined in the 'Verify KSR header' section of docs/ksr-processing.md."""
from logging import Logger

from kskm.common.config_misc import RequestPolicy
from kskm.common.validate import PolicyViolation
from kskm.ksr import Request


class KSR_HeaderPolicyViolation(PolicyViolation):
    """Policy violation in a KSRs header."""

    pass


class KSR_ID_Violation(KSR_HeaderPolicyViolation):
    """KSR-ID policy violation."""

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
        raise KSR_HeaderPolicyViolation(f'KSR-DOMAIN: Request domain {request.domain!r} not in '
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
      Verify that the KSR serial is unique and increasing for the KSR ID. This requires a list of all
      previously seen KSRs with the current KSR ID.
    """
    # TODO: Implement check of unique request SERIAL. As specified, this needs a database which we do not have.
    logger.info('KSR-SERIAL: Not implemented yet')
