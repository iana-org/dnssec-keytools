import logging
from typing import List

from kskm.misc.hsm import KSKM_P11

__author__ = 'ft'


logger = logging.getLogger(__name__)


def key_inventory(p11modules: KSKM_P11) -> List[str]:
    res: List[str] = []
    for module in p11modules:
        res += [str(module)]
        for slot, session in module.sessions.items():
            keys = module.get_key_inventory(session)
            if keys:
                res += [f'  Slot {slot}:']
            for key in keys:
                res += [f'    Key {key}']
                logger.info("hsm=%s %s", module.label, key.p11key)

    inv_str = '\n'.join(res)
    logger.debug(f'Key inventory:\n{inv_str}')
    return res
