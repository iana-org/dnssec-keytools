"""Generate and validate DNSSEC signatures for bundles."""

import base64
import binascii
import logging
import struct
from hashlib import sha256

from cryptography.exceptions import InvalidSignature

from kskm.common.data import Bundle, Key, Signature
from kskm.common.dnssec import key_to_rdata
from kskm.common.public_key import KSKM_PublicKey

__author__ = "ft"


_CLASS_IN = 1


logger = logging.getLogger(__name__)


def validate_signatures(bundle: Bundle) -> bool:
    """
    Make sure the sets of signatures and keys in a bundle are consistent.

    Will return True on successful validation, and raise an InvalidSignature exception otherwise.
    """
    # To locate keys for signatures, and to make sure all keys are covered by
    # a signature, we make a copy of the keys indexed by key_identifier.
    if not bundle.keys:
        raise ValueError(f"No keys in bundle {bundle.id}")

    if not bundle.signatures:
        raise ValueError(f"No signature in bundle {bundle.id}")

    # check for duplicate key_tags and build a convenient key_identifier -> key lookup dict
    _keys: dict[str, Key] = {}
    for key in bundle.keys:
        if key.key_identifier in _keys:
            raise ValueError(
                f"More than one key with key_identifier {key.key_identifier} in bundle {bundle.id}"
            )
        _keys[key.key_identifier] = key

    for sig in bundle.signatures:
        if sig.key_identifier not in _keys:
            raise ValueError(
                f"No key with key_identifier {sig.key_identifier} in bundle {bundle.id}"
            )
        key = _keys[sig.key_identifier]
        pubkey = KSKM_PublicKey.from_key(key)
        _sig_decoded = base64.b64decode(sig.signature_data)

        rrsig_raw = make_raw_rrsig(sig, bundle.keys)

        try:
            pubkey.verify_signature(_sig_decoded, rrsig_raw)
            _key_list = list(_keys.keys())
            logger.debug(f"Signature {sig.key_identifier} validates key(s) {_key_list}")
        except InvalidSignature:
            logger.error(
                f"Key {key.key_tag}/{key.key_identifier} in bundle {bundle.id} FAILED validation"
            )
            logger.debug(f"RRSIG: {binascii.hexlify(rrsig_raw)} ")
            logger.debug(f"DIGEST: {sha256(rrsig_raw).hexdigest()}")
            logger.debug(f"Public key: {pubkey}")
            raise
    return True


def make_raw_rrsig(sig: Signature, keys: set[Key]) -> bytes:
    """
    Create RRSIG raw data from a bundle.

    The RRSIG wire format is described in RFC4034, section 3.1.
    """
    res = struct.pack(
        "!HBBIIIH",
        sig.type_covered.value,
        sig.algorithm.value,
        sig.labels,
        sig.original_ttl,
        int(sig.signature_expiration.timestamp()),
        int(sig.signature_inception.timestamp()),
        sig.key_tag,
    )

    res += dn2wire(sig.signers_name)

    prefix = dn2wire(sig.signers_name)
    prefix += struct.pack(
        "!HHI",
        sig.type_covered.value,
        _CLASS_IN,
        sig.original_ttl,
    )

    # Construct a list of all the keys in wire format, so that we can sort them.
    # How this should be done is described in RFC4034 (6.3).
    rdata: list[bytes] = []
    for key in keys:
        rdata += [key_to_rdata(key)]

    # Add the sorted keys, each one with the common prefix.
    for this in sorted(rdata):
        length = struct.pack("!H", len(this))
        res += prefix + length + this
    return res


def dn2wire(dn: str) -> bytes:
    if dn == ".":
        return b"\00"
    raise NotImplementedError("Non-root dn2wire not implemented")


def dndepth(dn: str) -> int:
    """Return the number of DNS labels in a domain name (number of dots-1)."""
    if dn == ".":
        return 0
    raise NotImplementedError("Non-root dndepth not implemented")
