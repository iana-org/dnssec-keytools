"""Code to validate daisy-chain properties between KSR(n) and SKR(n-1)."""
import logging
from datetime import timedelta

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import Bundle
from kskm.common.display import format_bundles_for_humans
from kskm.common.validate import PolicyViolation
from kskm.ksr.data import Request
from kskm.skr.data import Response

__author__ = 'ft'

logger = logging.getLogger(__name__)


class KSR_CHAIN_Violation(PolicyViolation):
    """An issue has been found when checking KSR against SKR(n-1)."""

    pass


class KSR_CHAIN_KEYS_Violation(KSR_CHAIN_Violation):
    """KSR-CHAIN-KEYS policy violation."""

    pass


class KSR_CHAIN_OVERLAP_Violation(KSR_CHAIN_Violation):
    """KSR-CHAIN-OVERLAP policy violation."""

    pass


def check_chain(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """Validate that the current request continues a timeline ending with the previous response."""

    logger.info('Checking coherence between SKR(n-1) and this KSR')

    logger.debug('Last SKR (response):')
    [logger.debug(x) for x in format_bundles_for_humans(last_skr.bundles)]  # type: ignore
    logger.debug('This KSR (request):')
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
        logger.warning('KSR-CHAIN-KEYS: Checking published keys disabled by policy (check_chain_keys)')
        return

    last_key_set = last_skr.bundles[-1].keys
    first_key_set = ksr.bundles[0].keys
    logger.debug(f'Last key set in SKR(n-1): {last_key_set}')
    logger.debug(f'First key set in KSR: {first_key_set}')
    # TODO: Is this the correct definition of coherence? last_key_set will have had at least one KSK added to it,
    #       so we can't just check for equality. The last_key_set really depends on what schema was used at the
    #       last key ceremony, so I don't know how this can be checked beyond ensuring all keys in the first
    #       bundle of this KSR was also present in the last entry of the last SKR.
    for this in first_key_set:
        if this not in last_key_set:
            raise KSR_CHAIN_KEYS_Violation('Last key set in SKR(n-1) does not match first key set in KSR')

    logger.info(f'KSR-CHAIN-KEYS: The last keys in SKR(n-1) matches the first keys in this KSR')


def check_chain_overlap(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    if not policy.check_chain_overlap:
        logger.warning('KSR-CHAIN-OVERLAP: Checking chain signature overlap disabled by policy (check_chain_overlap)')
        return

    previous = last_skr.bundles[-1]
    ksr_first = ksr.bundles[0]

    overlap = previous.expiration - ksr_first.inception
    if overlap < ksr.zsk_policy.min_validity_overlap:
        logger.debug(f'Last bundle in SKR(n-1) expiration: {previous.expiration}')
        logger.debug(f'First bundle in KSR inception: {ksr_first.inception}')
        logger.error(f'Too small overlap of SKR(n-1) and KSR: {_fmt_timedelta(overlap)} < ' +
                     _fmt_timedelta(ksr.zsk_policy.min_validity_overlap))
        raise KSR_CHAIN_OVERLAP_Violation('Bundle "{}" (from SKR(n-1)) '
                                          'overlap {} with "{}" is < claimed minimum {}'.format(
            _fmt_bundle(ksr_first), _fmt_timedelta(overlap), _fmt_bundle(previous),
            _fmt_timedelta(ksr.zsk_policy.min_validity_overlap)
        ))
    if overlap > ksr.zsk_policy.max_validity_overlap:
        logger.debug(f'Last bundle in SKR(n-1) expiration: {previous.expiration}')
        logger.debug(f'First bundle in KSR inception: {ksr_first.inception}')
        logger.error(f'Too large overlap of SKR(n-1) and KSR: {_fmt_timedelta(overlap)} > ' +
                     _fmt_timedelta(ksr.zsk_policy.max_validity_overlap))
        raise KSR_CHAIN_OVERLAP_Violation('Bundle "{}" (from SRK(n-1)) '
                                          'overlap {} with "{}" is > claimed maximum {}'.format(
            _fmt_bundle(ksr_first), _fmt_timedelta(overlap), _fmt_bundle(previous),
            _fmt_timedelta(ksr.zsk_policy.max_validity_overlap),
        ))

    logger.info(f'KSR-CHAIN-OVERLAP: Overlap with last bundle in SKR(n-1) {_fmt_timedelta(overlap)} '
                f'is in accordance with the KSR policy')


def _fmt_bundle(bundle: Bundle) -> str:
    return 'id={} {}->{}'.format(bundle.id[:8],
                                 bundle.inception.isoformat().split('T')[0],
                                 bundle.expiration.isoformat().split('T')[0]
                                 )


def _fmt_timedelta(tdelta: timedelta) -> str:
    res = str(tdelta)
    if res.endswith('days, 0:00:00') or res.endswith('day, 0:00:00'):
        # cut off the unnecessary 0:00:00 after "days"
        res = res[:0 - len(', 0:00:00')]
    return res
