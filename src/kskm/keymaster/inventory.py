import logging
from typing import List

from kskm.misc.hsm import KSKM_P11, KeyClass

__author__ = 'ft'


logger = logging.getLogger(__name__)


def key_inventory(p11modules: KSKM_P11) -> List[str]:
    res: List[str] = []
    for module in p11modules:
        res += [f'HSM {module.label}:']
        for slot, session in sorted(module.sessions.items()):
            keys = dict()
            for this in module.get_key_inventory(session):
                if this.key_class not in keys:
                    keys[this.key_class] = {}
                if this.key_id in keys[this.key_class]:
                    logger.error(f'Key with class {this.key_class} and id {this.key_id} already seen in slot')
                    continue
                keys[this.key_class][this.key_id] = this

            formatted = _format_keys(keys)

            if formatted:
                res += [f'  Slot {slot}:']
                res += formatted
    return res

def _format_keys(data: dict) -> List[str]:
    res = []
    pairs = []
    # First, find all pairs (CKA_ID present in both PRIVATE and PUBLIC)
    if KeyClass.PUBLIC in data and KeyClass.PRIVATE in data:
        for key_id in sorted(list(data[KeyClass.PUBLIC].keys())):
            this = data[KeyClass.PUBLIC][key_id]
            if key_id in data[KeyClass.PRIVATE]:
                pairs += [f'      {this.label:7s} id={this.key_id} {str(this.pubkey)}']
                del data[KeyClass.PRIVATE][key_id]
            del data[KeyClass.PUBLIC][key_id]
    if pairs:
        res += ['    Signing key pairs:'] + pairs

    # Now, add all leftover keys
    for cls in data.keys():
        _res = []
        for key_id in sorted(list(data[cls].keys())):
            this = data[cls][key_id]
            _res += [f'      {this.label:7s} id={this.key_id}']
        if _res:
            res += [f'    {cls.name} keys:'] + _res

    return res
