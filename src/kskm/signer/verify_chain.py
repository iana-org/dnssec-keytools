"""Code to validate daisy-chain properties between KSR(n) and SKR(n-1)."""
import logging
from typing import Optional

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import FlagsDNSKEY
from kskm.common.display import fmt_bundle, fmt_timedelta, format_bundles_for_humans
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.validate import PolicyViolation
from kskm.ksr.data import Request
from kskm.misc.hsm import KSKM_P11, get_p11_key
from kskm.skr.data import Response

__author__ = "ft"

logger = logging.getLogger(__name__)


class KSR_CHAIN_Violation(PolicyViolation):
    """An issue has been found when checking KSR against SKR(n-1)."""


class KSR_CHAIN_KEYS_Violation(KSR_CHAIN_Violation):
    """KSR-CHAIN-KEYS policy violation."""


class KSR_CHAIN_OVERLAP_Violation(KSR_CHAIN_Violation):
    """KSR-CHAIN-OVERLAP policy violation."""


def check_chain(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """Validate that the current request continues a timeline ending with the previous response."""
    logger.info("Checking coherence between SKR(n-1) and this KSR")
    logger.debug("Last SKR (response):")
    [logger.debug(x) for x in format_bundles_for_humans(last_skr.bundles)]  # type: ignore
    logger.debug("This KSR (request):")
    [logger.debug(x) for x in format_bundles_for_humans(ksr.bundles)]  # type: ignore
    check_chain_keys(ksr, last_skr, policy)
    check_chain_overlap(ksr, last_skr, policy)


def check_chain_keys(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """
    Verify that last key set in last_skr matches first key set in ksr.

    KSR-CHAIN-KEYS:
      ... Then, to build the chain of trust linking the previous KSR to the current, the pre-published ZSK
      from the last key bundle of SKR(n-1) must match the ZSK published in the first key bundle of KSR(n),
      and the post-published ZSK from the first key bundle of KSR(n) must match the ZSKs published in the
      last key bundle of SKR(n-1).
    """
    if not policy.check_chain_keys:
        logger.warning(
            "KSR-CHAIN-KEYS: Checking published keys disabled by policy (check_chain_keys)"
        )
        return

    last_key_set = last_skr.bundles[-1].keys
    first_key_set = ksr.bundles[0].keys
    logger.debug(f"Last key set in SKR(n-1): {last_key_set}")
    logger.debug(f"First key set in KSR: {first_key_set}")

    for this in first_key_set:
        if this not in last_key_set:
            raise KSR_CHAIN_KEYS_Violation(
                "Last key set in SKR(n-1) does not match first key set in KSR"
            )
    logger.info(
        "KSR-CHAIN-KEYS: The last keys in SKR(n-1) matches the first keys in this KSR"
    )


def check_chain_overlap(
    ksr: Request, last_skr: Response, policy: RequestPolicy
) -> None:
    """Check signature chain overlap."""
    if not policy.check_chain_overlap:
        logger.warning(
            "KSR-CHAIN-OVERLAP: Checking chain signature overlap disabled by policy (check_chain_overlap)"
        )
        return

    previous = last_skr.bundles[-1]
    ksr_first = ksr.bundles[0]

    overlap = previous.expiration - ksr_first.inception
    if overlap < ksr.zsk_policy.min_validity_overlap:
        logger.debug(f"Last bundle in SKR(n-1) expiration: {previous.expiration}")
        logger.debug(f"First bundle in KSR inception: {ksr_first.inception}")
        logger.error(
            f"Too small overlap of SKR(n-1) and KSR: {fmt_timedelta(overlap)} < "
            + fmt_timedelta(ksr.zsk_policy.min_validity_overlap)
        )
        raise KSR_CHAIN_OVERLAP_Violation(
            'Bundle "{}" (from SKR(n-1)) '
            'overlap {} with "{}" is < claimed minimum {}'.format(
                fmt_bundle(ksr_first),
                fmt_timedelta(overlap),
                fmt_bundle(previous),
                fmt_timedelta(ksr.zsk_policy.min_validity_overlap),
            )
        )
    if overlap > ksr.zsk_policy.max_validity_overlap:
        logger.debug(f"Last bundle in SKR(n-1) expiration: {previous.expiration}")
        logger.debug(f"First bundle in KSR inception: {ksr_first.inception}")
        logger.error(
            f"Too large overlap of SKR(n-1) and KSR: {fmt_timedelta(overlap)} > "
            + fmt_timedelta(ksr.zsk_policy.max_validity_overlap)
        )
        raise KSR_CHAIN_OVERLAP_Violation(
            'Bundle "{}" (from SRK(n-1)) '
            'overlap {} with "{}" is > claimed maximum {}'.format(
                fmt_bundle(ksr_first),
                fmt_timedelta(overlap),
                fmt_bundle(previous),
                fmt_timedelta(ksr.zsk_policy.max_validity_overlap),
            )
        )

    logger.info(
        f"KSR-CHAIN-OVERLAP: Overlap with last bundle in SKR(n-1) {fmt_timedelta(overlap)} "
        f"is in accordance with the KSR policy"
    )


def check_last_skr_key_present(
    skr: Response, policy: RequestPolicy, p11modules: KSKM_P11 | None
) -> None:
    """Verify the KSK(s) that signed the last bundle in the SKR(n-1) is present in the available HSM(s)."""
    if not p11modules:
        # Skipped in some test cases
        logger.info("KSR-CHAIN-KEYS: Skipped when not passed an KSKM_P11")
        return
    if not policy.check_chain_keys_in_hsm:
        logger.warning(
            "KSR-CHAIN-KEYS: Checking published keys disabled by policy (check_chain_keys_present)"
        )
        return

    last_bundle = skr.bundles[-1]
    count = 0
    for sig in last_bundle.signatures:
        p11key = get_p11_key(sig.key_identifier, p11modules, public=True)
        if not p11key:
            raise KSR_CHAIN_KEYS_Violation(
                f"Key {sig.key_identifier} not found in the HSM(s) "
                f"(bundle {last_bundle.id})"
            )
        hsmkey = public_key_to_dnssec_key(
            key=p11key.public_key,  # type: ignore
            key_identifier=sig.key_identifier,
            algorithm=sig.algorithm,
            flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value,
            ttl=sig.ttl,
        )
        key = [x for x in last_bundle.keys if x.key_identifier == sig.key_identifier][0]
        if key.public_key != hsmkey.public_key:
            raise KSR_CHAIN_KEYS_Violation(
                f"Key {sig.key_identifier} does not match key in the HSM "
                f"(bundle {last_bundle.id})"
            )
        logger.debug(
            f"Key {sig.key_identifier} from last bundle in last SKR found in the HSM(s) "
            f"(bundle {last_bundle.id})"
        )
        count += 1
    if not count:
        raise KSR_CHAIN_KEYS_Violation(
            "KSR-CHAIN-KEYS: No signatures in the last bundle of the last SKR"
        )
    logger.info(
        f"KSR-CHAIN-KEYS: All {count} signatures in the last bundle of the last SKR were made with keys "
        "present in the HSM(s)"
    )
