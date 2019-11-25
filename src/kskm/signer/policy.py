"""Combined policy checks for last SKR+KSR."""
import logging
from datetime import datetime, timedelta
from typing import Optional

from kskm.common.config_misc import RequestPolicy
from kskm.ksr import Request
from kskm.ksr.verify_bundles import KSR_BUNDLE_UNIQUE_Violation
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.misc.hsm import KSKM_P11
from kskm.signer.verify_chain import check_chain, check_last_skr_key_present
from kskm.skr import Response

__author__ = 'ft'


logger = logging.getLogger(__name__)


def check_skr_and_ksr(ksr: Request, last_skr: Response, policy: RequestPolicy, p11modules: Optional[KSKM_P11]) -> None:
    """Perform some policy checks that validates consistency from last SKR to this KSR."""
    check_unique_ids(ksr, last_skr, policy)
    check_chain(ksr, last_skr, policy)
    check_last_skr_key_present(last_skr, policy, p11modules)


def check_last_skr_and_new_skr(last_skr: Response, new_skr: Response, policy: RequestPolicy) -> None:
    """Validate that the new SKR is coherent with the last SKR."""
    check_skr_timeline(last_skr, new_skr, policy)


def check_unique_ids(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Request ID can't be the same in this KSR and the last SKR.

    Bundle IDs have to be unique within the last SKR and the KSR.
    """
    check_unique_request(ksr, last_skr, policy)
    check_unique_bundle_ids(ksr, last_skr, policy)


def check_unique_request(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Check the ID in the request.

    KSR-ID:
      Verify that the KSR ID is unique.

    The KSR request ID is echoed in the SKR response ID, so by comparing this KSR's ID with the
    last responses ID we make sure the KSR isn't a resend/replay of the previous KSR.
    """
    if ksr.id == last_skr.id:
        raise KSR_ID_Violation(f'The KSR request ID is the same as the last SKR ID: {ksr.id}')


def check_unique_bundle_ids(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Check the Bundle IDs in the request and make sure they are not also present in the last SKR.

    KSR-BUNDLE-UNIQUE:
      Verify that all requested bundles has unique IDs

    Since we don't keep a database with all the KSRs/SKRs ever seen/generated, this requirement
    is interpreted as checking for uniqueness where we can.
    """
    for ksr_bundle in ksr.bundles:
        for skr_bundle in last_skr.bundles:
            if ksr_bundle.id == skr_bundle.id:
                raise KSR_BUNDLE_UNIQUE_Violation(f'A bundle with id {ksr_bundle.id} was also present in the last SKR')


def check_skr_timeline(last_skr: Response, new_skr: Response, policy: RequestPolicy) -> None:
    """
    Ensure all keys in the last SKR and this one will be published and retired according to policy.

    KSR-POLICY-SAFETY:
    Verify _PublishSafety_ and _RetireSafety_ periods. A key must be published at least _PublishSafety_ before
    being used for signing and at least _RetireSafety_ before being removed after it is no longer used for signing.
    """
    # TODO: Build a timeline of all slots in last SKR, followed by the slots from the KSR
    #       with the schema in use applied. Then check that all published/retired keys are
    #       within the safety parameters.
    logger.warning('Check KSR-POLICY-SAFETY not implemented yet')
    pass


def _fmt_timedelta(tdelta: timedelta) -> str:
    res = str(tdelta)
    if res.endswith('days, 0:00:00') or res.endswith('day, 0:00:00'):
        # cut off the unnecessary 0:00:00 after "days"
        res = res[:0 - len(', 0:00:00')]
    return res


def _fmt_timestamp(ts: datetime) -> str:
    return ts.isoformat().split('+')[0]
