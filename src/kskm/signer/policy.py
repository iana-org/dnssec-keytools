"""Combined policy checks for last SKR+KSR."""
import logging

from kskm.common.config_misc import RequestPolicy
from kskm.ksr import Request
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.signer.daisy import check_daisy_chain
from kskm.skr import Response

__author__ = 'ft'


logger = logging.getLogger(__name__)


def check_skr_and_ksr(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """Perform some policy checks that validates consistency from last SKR to this KSR."""
    check_unique_ids(ksr, last_skr, policy)
    check_daisy_chain(ksr, last_skr, policy)
    check_timeline(ksr, last_skr, policy)


def check_unique_ids(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Request ID can't be the same in this KSR and the last SKR.

    Bundle IDs have to be unique within the last SKR and the KSR.
    """
    check_unique_request(ksr, last_skr, policy)


def check_unique_request(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    if ksr.id == last_skr.id:
        raise KSR_ID_Violation(f'The KSR request ID is the same as the last SKR ID: {ksr.id}')


def check_timeline(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    KSR-POLICY-SAFETY:
    Verify _PublishSafety_ and _RetireSafety_ periods. A key must be published at least _PublishSafety_ before
    being used for signing and at least _RetireSafety_ before being removed after it is no longer used for signing.
    """

    # TODO: Build a timeline of all slots in last SKR, followed by the slots from the KSR
    #       with the schema in use applied. Then check that all published/retired keys are
    #       within the safety parameters.
    logger.warning('Check KSR-POLICY-SAFETY not implemented yet')
    pass
