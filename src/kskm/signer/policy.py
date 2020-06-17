"""Combined policy checks for last SKR+KSR."""
import logging
from typing import Optional

from kskm.common.config_misc import RequestPolicy
from kskm.common.display import fmt_timedelta, format_bundles_for_humans
from kskm.ksr import Request
from kskm.ksr.verify_bundles import KSR_BUNDLE_UNIQUE_Violation
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.ksr.verify_policy import KSR_POLICY_SAFETY_Violation
from kskm.misc.hsm import KSKM_P11
from kskm.signer.verify_chain import check_chain, check_last_skr_key_present
from kskm.skr import Response

__author__ = "ft"


logger = logging.getLogger(__name__)


def check_skr_and_ksr(
    ksr: Request,
    last_skr: Response,
    policy: RequestPolicy,
    p11modules: Optional[KSKM_P11],
) -> None:
    """Perform some policy checks that validates consistency from last SKR to this KSR."""
    check_unique_ids(ksr, last_skr, policy)
    check_chain(ksr, last_skr, policy)
    check_last_skr_key_present(last_skr, policy, p11modules)


def check_last_skr_and_new_skr(
    last_skr: Response, new_skr: Response, policy: RequestPolicy
) -> None:
    """Validate that the new SKR is coherent with the last SKR."""
    check_publish_safety(last_skr, new_skr, policy)
    check_retire_safety(last_skr, new_skr, policy)


def check_unique_ids(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Request ID can't be the same in this KSR and the last SKR.

    Bundle IDs have to be unique within the last SKR and the KSR.
    """
    check_unique_request(ksr, last_skr, policy)
    check_unique_bundle_ids(ksr, last_skr, policy)


def check_unique_request(
    ksr: Request, last_skr: Response, policy: RequestPolicy
) -> None:
    """
    Check the ID in the request.

    KSR-ID:
      Verify that the KSR ID is unique.

    The KSR request ID is echoed in the SKR response ID, so by comparing this KSR's ID with the
    last responses ID we make sure the KSR isn't a resend/replay of the previous KSR.
    """
    if ksr.id == last_skr.id:
        raise KSR_ID_Violation(
            f"The KSR request ID is the same as the last SKR ID: {ksr.id}"
        )


def check_unique_bundle_ids(
    ksr: Request, last_skr: Response, policy: RequestPolicy
) -> None:
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
                raise KSR_BUNDLE_UNIQUE_Violation(
                    f"A bundle with id {ksr_bundle.id} was also present in the last SKR"
                )


def check_publish_safety(
    last_skr: Response, new_skr: Response, policy: RequestPolicy
) -> None:
    """
    Ensure all keys in the last SKR and this one will be published according to policy.

    KSR-POLICY-SAFETY:
    Verify _PublishSafety_ and _RetireSafety_ periods. A key must be published at least _PublishSafety_ before
    being used for signing and at least _RetireSafety_ before being removed after it is no longer used for signing.
    """
    if not policy.check_keys_publish_safety:
        logger.warning(
            "KSR-POLICY-SAFETY: PublishSafety checking disabled by policy (check_keys_publish_safety)"
        )
        return

    # First, check that all keys used to sign bundle[0] of the new_skr was published in the
    # last bundle of last_skr.
    _last_bundle = last_skr.bundles[-1]
    for sig in new_skr.bundles[0].signatures:
        _match = [
            x for x in _last_bundle.keys if x.key_identifier == sig.key_identifier
        ]
        if not _match:
            logger.info("Last SKR:")
            for _msg in format_bundles_for_humans(last_skr.bundles):
                logger.info(_msg)
            logger.info("New SKR:")
            for _msg in format_bundles_for_humans(new_skr.bundles):
                logger.info(_msg)
            logger.error(
                f"Key {sig.key_identifier} from bundle {new_skr.bundles[0].id} not found in keys from "
                f"last bundle ({last_skr.bundles[-1].id}) from last SKR"
            )
            raise KSR_POLICY_SAFETY_Violation(
                f"Key {sig.key_identifier} used to sign the first bundle in this SKR "
                f"was not present in the last bundle of the last SKR"
            )

    # Now, check that the new SKRs inception time minus the PublishSafety falls within the inception
    # and expiration of this last bundle where we've verified the current signing key was published
    _publish_dt = new_skr.bundles[0].inception - new_skr.ksk_policy.publish_safety
    _last_inception = _last_bundle.inception
    if _publish_dt < _last_inception:
        raise KSR_POLICY_SAFETY_Violation(
            f"The ZSK policy publish safety point in time ({_publish_dt}) occurred "
            f"before the inception of the last bundle in the last SKR "
            f"({_last_inception})"
        )
    _last_expiration = _last_bundle.expiration
    if _publish_dt > _last_expiration:
        raise KSR_POLICY_SAFETY_Violation(
            f"The ZSK policy publish safety point in time ({_publish_dt}) occurred "
            f"after the expiration of the last bundle in the last SKR "
            f"({_last_inception})"
        )
    logger.info("KSR-POLICY-SAFETY: PublishSafety validated")


def check_retire_safety(
    last_skr: Response, new_skr: Response, policy: RequestPolicy
) -> None:
    """
    Ensure all keys in the last SKR and this one will be retired according to policy.

    KSR-POLICY-SAFETY:
    Verify _PublishSafety_ and _RetireSafety_ periods. A key must be published at least _PublishSafety_ before
    being used for signing and at least _RetireSafety_ before being removed after it is no longer used for signing.
    """
    if not policy.check_keys_retire_safety:
        logger.warning(
            "KSR-POLICY-SAFETY: RetireSafety checking disabled by policy (check_keys_retire_safety)"
        )
        return

    # Figure out the point in time where a signing key from the last bundle in the last SKR is required to
    # still be published in this SKR.
    last_bundle = last_skr.bundles[-1]
    first_bundle = new_skr.bundles[0]
    retire_at = first_bundle.inception + new_skr.ksk_policy.retire_safety
    for bundle in new_skr.bundles:
        if bundle.inception <= retire_at:
            # This bundle must include all the signing keys from the last bundle
            for sig in last_bundle.signatures:
                _match = [
                    x for x in bundle.keys if x.key_identifier == sig.key_identifier
                ]
                if not _match:
                    for _msg in format_bundles_for_humans(new_skr.bundles):
                        logger.info(_msg)
                    _retire_safety = fmt_timedelta(new_skr.ksk_policy.retire_safety)
                    raise KSR_POLICY_SAFETY_Violation(
                        f"Key {sig.key_tag}/{sig.key_identifier} used to sign bundle "
                        f"{last_bundle.id} in the last SKR is not present in bundle "
                        f"{bundle.id} which expires < RetireSafety "
                        f"({_retire_safety}/{retire_at}) from this new SKRs first "
                        f"bundle inception ({first_bundle.inception})"
                    )

    # Now, ensure that a key used to sign a bundle in the new SKR doesn't disappear later in this SKR
    # (this is to support the assumption made above that all the signing keys are present in the last bundle)
    _curr_idx = 1
    for _curr in new_skr.bundles:
        # Take a simplified approach and just verify that all signing keys of a bundle is
        # present in all the following bundles in this SKR
        _curr_key_ids = [x.key_identifier for x in _curr.keys]
        for _check_idx in range(_curr_idx, len(new_skr.bundles)):
            bundle = new_skr.bundles[_check_idx]
            for sig in _curr.signatures:
                _match = [
                    x for x in bundle.keys if x.key_identifier == sig.key_identifier
                ]
                if not _match:
                    for _msg in format_bundles_for_humans(new_skr.bundles):
                        logger.info(_msg)
                    raise KSR_POLICY_SAFETY_Violation(
                        f"Key {sig.key_tag}/{sig.key_identifier} used to sign bundle "
                        f"#{_curr_idx} ({_curr.id}) in this SKR is not present in bundle "
                        f"#{_check_idx} ({bundle.id})"
                    )
        _curr_idx += 1

    logger.info(f"KSR-POLICY-SAFETY: RetireSafety validated")
