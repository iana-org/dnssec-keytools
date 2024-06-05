"""Key inventory functions."""

import logging
from binascii import hexlify

from kskm.common.config import KSKMConfig
from kskm.common.config_ksk import validate_dnskey_matches_ksk
from kskm.common.data import FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.misc.hsm import KSKM_P11, KeyClass, KeyInfo

__author__ = "ft"


logger = logging.getLogger(__name__)


def key_inventory(p11modules: KSKM_P11, config: KSKMConfig) -> list[str]:
    """Return key inventory."""
    res: list[str] = []
    for module in p11modules:
        res += [f"HSM {module.label}:"]
        for slot, session in sorted(module.sessions.items()):
            keys: dict[KeyClass, dict[str, KeyInfo]] = dict()
            for this in module.get_key_inventory(session):
                if this.key_class not in keys:
                    keys[this.key_class] = {}
                label_and_id = f"{this.label}+{this.key_id!r}"
                if label_and_id in keys[this.key_class]:
                    logger.error(
                        f"Key with class {this.key_class} and label+id {label_and_id} already seen in slot"
                    )
                    continue
                keys[this.key_class][label_and_id] = this

            formatted = _format_keys(keys, config)

            if formatted:
                res += [f"  Slot {slot}:"]
                res += formatted
    return res


def _format_keys(
    data: dict[KeyClass, dict[str, KeyInfo]], config: KSKMConfig
) -> list[str]:
    """Format keys for inventory."""
    res: list[str] = []
    pairs: list[str] = []
    # First, find all pairs (CKA_LABEL+CKA_ID present in both PRIVATE and PUBLIC)
    if KeyClass.PUBLIC in data and KeyClass.PRIVATE in data:
        # make copy of keys to be able to remove elements from dict below
        initial_keylist = list(data[KeyClass.PUBLIC].keys())
        for label_and_id in initial_keylist:
            this = data[KeyClass.PUBLIC][label_and_id]
            if this.pubkey is None:
                raise RuntimeError("Invalid public key")

            ksk_info = "Matching KSK not found in configuration"
            # Look for the key in the config
            for _name, ksk in config.ksk_keys.items():
                if ksk.label == this.label:
                    dnskey = public_key_to_dnssec_key(
                        public_key=this.pubkey,
                        key_identifier=this.label,
                        algorithm=ksk.algorithm,
                        flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value,
                        ttl=0,
                    )

                    # Check that key found in HSM matches the configuration
                    try:
                        validate_dnskey_matches_ksk(ksk, dnskey)
                    except RuntimeError as exc:
                        ksk_info = (
                            f"BAD KSK '{ksk.label}/{ksk.description}': {str(exc)}"
                        )
                        break

                    ksk_info = (
                        f"KSK '{ksk.label}/{ksk.description}', key tag {ksk.key_tag}, "
                        f"algorithm={ksk.algorithm.name}"
                    )

            if label_and_id in data[KeyClass.PRIVATE]:
                pairs += [
                    f"      {this.label:7s} {_id_to_str(this.key_id)}{str(this.pubkey)} -- {ksk_info}"
                ]
                del data[KeyClass.PRIVATE][label_and_id]
            del data[KeyClass.PUBLIC][label_and_id]
    if pairs:
        res += ["    Signing key pairs:"] + pairs

    # Now, add all leftover keys
    for cls in data:
        _leftovers: list[str] = []
        for this in list(data[cls].values()):
            _leftovers += [f"      {this.label:7s} {_id_to_str(this.key_id)}"]
        if _leftovers:
            res += [f"    {cls.name} keys:"] + _leftovers
    return res


def _id_to_str(key_id: bytes | None) -> str:
    """
    Format CKA_ID as string.

    :return: A string suitable for printing (prefixed with 'id=0x' and suffixed with ' '), or an empty string.
    """
    if key_id:
        return f"id=0x{hexlify(key_id).decode()} "
    return ""
