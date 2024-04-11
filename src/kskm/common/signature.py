"""Generate and validate DNSSEC signatures for bundles."""

import base64
import binascii
import logging
import struct
from hashlib import sha256
from typing import Dict, List, Set

from kskm.common.data import Bundle, Key, Signature
from kskm.common.dnssec import key_to_rdata
from kskm.common.ecdsa_utils import (
    algorithm_to_curve,
    decode_ecdsa_public_key,
    is_algorithm_ecdsa,
)
from kskm.common.rsa_utils import decode_rsa_public_key, is_algorithm_rsa
from kskm.misc.crypto import InvalidSignature, key_to_crypto_pubkey, verify_signature

__author__ = "ft"


_CLASS_IN = 1


logger = logging.getLogger(__name__)


def validate_signatures(bundle: Bundle) -> bool:
    """
    Make sure the sets of signatures and keys in a bundle is consistent.

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
        pubkey = key_to_crypto_pubkey(key)
        _sig_decoded = base64.b64decode(sig.signature_data)

        rrsig_raw = make_raw_rrsig(sig, bundle.keys)

        try:
            verify_signature(pubkey, _sig_decoded, rrsig_raw, key.algorithm)
            _key_list = list(_keys.keys())
            logger.debug(f"Signature {sig.key_identifier} validates key(s) {_key_list}")
        except InvalidSignature:
            logger.error(
                "Key %s/%s in bundle %s FAILED validation",
                key.key_tag,
                key.key_identifier,
                bundle.id,
            )
            logger.debug("RRSIG:  %s", binascii.hexlify(rrsig_raw))
            logger.debug("DIGEST: %s", sha256(rrsig_raw).hexdigest())
            if is_algorithm_rsa(key.algorithm):
                _rsa_pk = decode_rsa_public_key(key.public_key)
                logger.debug(f"Public key: {_rsa_pk}")
            elif is_algorithm_ecdsa(key.algorithm):
                _ecdsa_pk = decode_ecdsa_public_key(
                    key.public_key, algorithm_to_curve(key.algorithm)
                )
                logger.debug(f"Public key: {_ecdsa_pk}")
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

    res += _dn2wire(sig.signers_name)

    prefix = _dn2wire(sig.signers_name)
    prefix += struct.pack("!HHI", sig.type_covered.value, _CLASS_IN, sig.original_ttl,)

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


def _dn2wire(dn: str) -> bytes:
    if dn == ".":
        return b"\00"
    raise NotImplementedError("Non-root dn2wire not implemented")


def dndepth(dn: str) -> int:
    """Return the number of DNS labels in a domain name (number of dots-1)."""
    if dn == ".":
        return 0
    raise NotImplementedError("Non-root dndepth not implemented")
