"""KSK Configuration Validation functions."""

import binascii
import logging

from kskm.common.config_misc import KSKKey
from kskm.common.data import Key
from kskm.ta.keydigest import create_trustanchor_keydigest

__author__ = "ft"

logger = logging.getLogger(__name__)


def validate_dnskey_matches_ksk(ksk: KSKKey, dnskey: Key) -> None:
    """Check that a loaded key matches the configured key (KSK)."""
    if not ksk.ds_sha256:
        logger.warning(
            f"Key {ksk.label} does not have a DS SHA256 specified - "
            f"can't ensure the right key was in the HSM"
        )
    else:
        _ds = create_trustanchor_keydigest(ksk, dnskey)
        digest = binascii.hexlify(_ds.digest).decode("UTF-8").upper()
        ksk_digest = ksk.ds_sha256.upper()
        if ksk_digest != digest:
            logger.error(
                f"Configured KSK key {ksk.label} DS SHA256 {ksk_digest} does not match computed "
                f"DS SHA256 {digest} for DNSSEC key: {dnskey}"
            )
            raise RuntimeError(
                f"Key {ksk.label} has unexpected DS ({digest}, not {ksk_digest})"
            )
    if ksk.key_tag is None:
        logger.warning(
            f"Key {ksk.label} does not have a key tag specified - "
            f"can't ensure the right key was in the HSM"
        )
    elif dnskey.key_tag != ksk.key_tag:
        logger.error(
            f"Configured KSK key {ksk.label} key tag {ksk.key_tag} does not match key tag "
            f"{dnskey.key_tag} for DNSSEC key: {dnskey}"
        )
        raise RuntimeError(
            f"Key {ksk.label} has unexpected key tag ({dnskey.key_tag}, not {ksk.key_tag})"
        )
