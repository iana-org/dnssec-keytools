"""Combined policy checks for last SKR+KSR."""
from kskm.common.config_misc import RequestPolicy
from kskm.ksr import Request
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.signer.daisy import check_daisy_chain
from kskm.skr import Response


def check_skr_and_ksr(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """Perform some policy checks that validates consistency from last SKR to this KSR."""
    check_unique_ids(ksr, last_skr, policy)
    check_daisy_chain(ksr, last_skr, policy)


def check_unique_ids(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Request ID can't be the same in this KSR and the last SKR.

    Bundle IDs have to be unique within the last SKR and the KSR.
    """
    check_unique_request(ksr, last_skr, policy)


def check_unique_request(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    if ksr.id == last_skr.id:
        raise KSR_ID_Violation(f'The KSR request ID is the same as the last SKR ID: {ksr.id}')
