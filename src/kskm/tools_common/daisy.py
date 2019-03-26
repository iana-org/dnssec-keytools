""" Code to validate daisy-chain propertys between KSR(n) and SKR(n-1). """

import logging
from datetime import datetime
from dataclasses import dataclass

from typing import List, Sequence

from kskm.common.data import Key
from kskm.common.parse_utils import is_zsk_key
from kskm.ksr.policy import RequestPolicy
from kskm.common.validate import PolicyViolation, fail
from kskm.ksr.data import Request, Bundle
from kskm.skr.data import Response
from kskm.tools_common.display import format_bundles_for_humans


logger = logging.getLogger(__name__)


class DaisyChainOrderViolation(PolicyViolation):
    pass

# TODO: We don't actually do anything with the timestamps in DaisyTime, should we?
@dataclass(frozen=True, repr=False)
class DaisyTime(object):
    inception: datetime
    expiration: datetime
    key: Key

    def __repr__(self) -> str:
        return 'DaisyTime(keytag={}, inception={}, expiration={})'.format(
            self.key.key_tag, self.inception, self.expiration)


# TODO: We don't actually do anything with more than one 'curr'.
#       The code below could be made simpler and more readable if curr was not a list.
@dataclass(frozen=True)
class DaisyChain(object):
    prev: DaisyTime         # ZSK(n-1)
    curr: List[DaisyTime]   # ZSK(n)
    next: DaisyTime         # ZSK(n+1)


def check_daisy_chain(ksr: Request, last_skr: Response, policy: RequestPolicy) -> None:
    """Validate that the current request continues a timeline ending with the previous response."""
    if not policy.check_request_daisy_chain:
        return

    logger.debug('Last SKR (response):')
    [logger.debug(x) for x in format_bundles_for_humans(last_skr.bundles)] # type: ignore

    ksr_chain = _daisychain_from_bundle(ksr.bundles)
    last_chain = _daisychain_from_bundle(last_skr.bundles)

    if ksr_chain.prev.key != last_chain.curr[-1].key:
        logger.info('KSR {} previous key: {}'.format(ksr.id, ksr_chain.prev.key))
        logger.info('Last SKR {} current key: {}'.format(last_skr.id, last_chain.curr[-1].key))
        fail(policy, DaisyChainOrderViolation, 'KSR previous key {} does not match last SKR current key {}'.format(
            ksr_chain.prev.key.key_tag, last_chain.curr[-1].key.key_tag))
    else:
        _this = ksr_chain.prev.key
        logger.debug('KSR previous key matches last SKR current key: {}({})'.format(_this.key_tag, _this.key_identifier))

    if ksr_chain.curr[0].key != last_chain.next.key:
        logger.info('KSR {} current key: {}'.format(ksr.id, ksr_chain.curr[0].key))
        logger.info('Last SKR {} next key: {}'.format(last_skr.id, last_chain.next.key))
        fail(policy, DaisyChainOrderViolation, 'KSR current key {} does not match last SKR next key {}'.format(
            ksr_chain.curr[0].key.key_tag, last_chain.next.key.key_tag))
    else:
        _this = ksr_chain.curr[0].key
        logger.debug('KSR current key matches last SKR next key: {}({})'.format(_this.key_tag, _this.key_identifier))


def _daisychain_from_bundle(bundles: Sequence[Bundle]) -> DaisyChain:
    """Extract all ZSKs from the bundles and build up a DaisyChain with the previous, current and next keys."""
    _curr_keylist = [x for x in list(bundles[1].keys) if is_zsk_key(x)]
    if len(_curr_keylist) != 1:
        raise RuntimeError('The second bundle ({}) did not contain exactly one ZSK key'.format(bundles[1].id))
    curr_key = _curr_keylist[0]
    prev = None
    next = None
    curr: List[DaisyTime] = []
    for this in bundles:
        for key in [x for x in this.keys if is_zsk_key(x)]:
            _res = DaisyTime(this.inception, this.expiration, key)
            if key == curr_key:
                curr += [_res]
            elif this == bundles[0]:
                assert prev is None
                prev = _res
            elif this == bundles[-1]:
                assert next is None
                next = _res
            else:
                raise RuntimeError('More than three keys in bundles')
    # TODO: Think there was one KSR in the archive where next was the same as curr?
    assert prev is not None
    assert next is not None
    return DaisyChain(prev=prev, curr=sorted(curr, key=lambda x: x.expiration), next=next)
