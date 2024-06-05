"""Key inventory functions."""

import logging
from binascii import hexlify

from pydantic import BaseModel

from kskm.common.config import KSKMConfig
from kskm.common.config_ksk import validate_dnskey_matches_ksk
from kskm.common.data import FlagsDNSKEY, Key
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.misc.hsm import KSKM_P11, KeyClass, KeyInfo
from kskm.ta.data import KeyDigest
from kskm.ta.keydigest import create_trustanchor_keydigest

from base64 import b64encode
from datetime import UTC, datetime

from pydantic import BaseModel

from kskm.common.config import KSKMConfig
from kskm.common.config_misc import KSKKey
from kskm.common.data import FlagsDNSKEY, Key
from kskm.common.dnssec import public_key_to_dnssec_key

from kskm.ta.data import KeyDigest
from kskm.ta.keydigest import create_trustanchor_keydigest
from kskm.version import __verbose_version__

__author__ = "ft"


logger = logging.getLogger(__name__)


def key_inventory(p11modules: KSKM_P11, config: KSKMConfig, dns_records: bool) -> list[str]:
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

            formatted = _format_keys(keys, config, dns_records)

            if formatted:
                res += [f"  Slot {slot}:"]
                res += formatted
    return res


def _format_keys(
    data: dict[KeyClass, dict[str, KeyInfo]], config: KSKMConfig, dns_records: bool
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
            dns = None
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

                    dns = key_to_dns_records(dnskey)

            if label_and_id in data[KeyClass.PRIVATE]:
                pairs += [
                    f"      {this.label:7s} {_id_to_str(this.key_id)}{this.pubkey.decode()} -- {ksk_info}"
                ]

                if dns_records and dns:
                    pairs += [f"              {dns.ds_rr}"]
                    pairs += [f"              {dns.dnskey_rr}"]
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

class DNSRecords(BaseModel):
    """DNS records for a key"""

    ds_rr: str
    dnskey_rr: str
    ds: KeyDigest

    def __str__(self) -> str:
        return f"{self.ds_rr}\n{self.dnskey_rr}"

def key_to_dns_records(key: Key) -> DNSRecords:
    """ Format DNS records (DS, DNSKEY) for a Key instance """

    _now = datetime.now(UTC)
    # create_trustanchor_keydigest wants an KSKKey, but it is not used in the digest calculation
    _temp_ksk = KSKKey(
        description="Newly generated key",
        label=f"temp_{key.key_tag}",
        key_tag=key.key_tag,
        algorithm=key.algorithm,
        valid_from=_now,
        valid_until=_now,
    )
    _domain = "."
    _ds = create_trustanchor_keydigest(_temp_ksk, key, domain=_domain)
    digest = hexlify(_ds.digest).decode("UTF-8").upper()
    _digest_type = "2"  # create_trustanchor_keydigest always does SHA256
    ds_str = f"{_domain} IN DS {key.key_tag} {key.algorithm.value} {_digest_type} {digest}"

    dnskey_str = (f"{_domain} IN DNSKEY {key.flags} {key.protocol} {key.algorithm.value} "
        f"{b64encode(key.public_key).decode()}"
    )

    return DNSRecords(ds_rr=ds_str, dnskey_rr=dnskey_str, ds=_ds)
