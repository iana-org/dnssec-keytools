import logging
from typing import Dict, List

from kskm.common.config import KSKMConfig
from kskm.common.config_ksk import validate_dnskey_matches_ksk
from kskm.common.data import FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.misc.hsm import KSKM_P11, KeyClass

__author__ = 'ft'


logger = logging.getLogger(__name__)


def key_inventory(p11modules: KSKM_P11, config: KSKMConfig) -> List[str]:
    res: List[str] = []
    for module in p11modules:
        res += [f'HSM {module.label}:']
        for slot, session in sorted(module.sessions.items()):
            keys: Dict[KeyClass, dict] = dict()
            for this in module.get_key_inventory(session):
                if this.key_class not in keys:
                    keys[this.key_class] = {}
                if this.key_id in keys[this.key_class]:
                    logger.error(f'Key with class {this.key_class} and id {this.key_id} already seen in slot')
                    continue
                keys[this.key_class][this.key_id] = this

            formatted = _format_keys(keys, config)

            if formatted:
                res += [f'  Slot {slot}:']
                res += formatted
    return res


def _format_keys(data: dict, config: KSKMConfig) -> List[str]:
    res: List[str] = []
    pairs: List[str] = []
    # First, find all pairs (CKA_ID present in both PRIVATE and PUBLIC)
    if KeyClass.PUBLIC in data and KeyClass.PRIVATE in data:
        for key_id in data[KeyClass.PUBLIC].keys():
            this = data[KeyClass.PUBLIC][key_id]

            ksk_info = 'Matching KSK not found in configuration'
            # Look for the key in the config
            for _name, ksk in config.ksk_keys.items():
                if ksk.label == this.label:
                    dnskey = public_key_to_dnssec_key(key=this.pubkey,
                                                      key_identifier=this.label,
                                                      algorithm=ksk.algorithm,
                                                      flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value,
                                                      ttl=0,
                                                      )

                    # Check that key found in HSM matches the configuration
                    try:
                        validate_dnskey_matches_ksk(ksk, dnskey)
                    except RuntimeError as exc:
                        ksk_info = f'BAD KSK \'{ksk.label}/{ksk.description}\': {str(exc)}'
                        break

                    ksk_info = f'KSK \'{ksk.label}/{ksk.description}\', key tag {ksk.key_tag}, ' \
                        f'algorithm={ksk.algorithm.name}'

            if key_id in data[KeyClass.PRIVATE]:
                pairs += [f'      {this.label:7s} id={this.key_id} {str(this.pubkey)} -- {ksk_info}']
                data[KeyClass.PRIVATE][key_id] = None
            data[KeyClass.PUBLIC][key_id] = None
    if pairs:
        res += ['    Signing key pairs:'] + pairs

    # Now, add all leftover keys
    for cls in data.keys():
        _res: List[str] = []
        for key_id in list(data[cls].keys()):
            this = data[cls][key_id]
            if this is None:
                continue
            _res += [f'      {this.label:7s} id={this.key_id}']
        if _res:
            res += [f'    {cls.name} keys:'] + _res

    return res
