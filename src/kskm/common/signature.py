"""Generate and validate DNSSEC signatures for bundles."""

import base64
import binascii
import logging
import struct
from hashlib import sha256
from typing import Dict, List, Set

from kskm.common.data import Bundle, Key, Signature
from kskm.common.dnssec import key_to_rdata
from kskm.common.rsa_utils import decode_rsa_public_key, is_algorithm_rsa
from kskm.misc.crypto import (InvalidSignature, key_to_crypto_pubkey,
                              verify_signature)

__author__ = 'ft'


_CLASS_IN = 1


logger = logging.getLogger(__name__)


def validate_signatures(bundle: Bundle) -> bool:
    """
    Make sure the sets of signatures and keys in a bundle is consistent.

    Will return True on successful validation, and raise an InvalidSignature exception otherwise.
    """
    # To locate keys for signatures, and to make sure all keys are covered by
    # a signature, we make a copy of the keys indexed by key_tag.
    if not bundle.keys:
        raise ValueError('No keys in bundle {}'.format(bundle.id))

    if not bundle.signatures:
        raise ValueError('No signature in bundle {}'.format(bundle.id))

    # check for duplicate key_tags and build a convenient key_tag -> key lookup dict
    _keys: Dict[int, Key] = {}
    for key in bundle.keys:
        if key.key_tag in _keys:
            raise ValueError('More than one key with key_tag {} in bundle {}'.format(key.key_tag, bundle.id))
        _keys[key.key_tag] = key

    for sig in bundle.signatures:
        if sig.key_tag not in _keys:
            raise ValueError('No key with key_tag {} in bundle {}'.format(sig.key_tag, bundle.id))
        key = _keys[sig.key_tag]
        if not _is_rsa_key(key):
            raise NotImplementedError('Can only verify RSA signatures (not {})'.format(key.algorithm))
        pubkey = key_to_crypto_pubkey(key)
        _sig_decoded = base64.b64decode(sig.signature_data)

        rrsig_raw = make_raw_rrsig(sig, bundle.keys)

        try:
            verify_signature(pubkey, _sig_decoded, rrsig_raw, key.algorithm)
            _key_list = list(_keys.keys())
            logger.debug(f'Signature {sig.key_tag} validates key(s) {_key_list}')
        except InvalidSignature:
            logger.error(f'Key {key.key_tag}/{key.key_identifier} in bundle {bundle.id} FAILED validation')
            logger.debug('RRSIG : {}'.format(binascii.hexlify(rrsig_raw)))
            logger.debug('DIGEST: {}'.format(sha256(rrsig_raw).hexdigest()))
            _pk = decode_rsa_public_key(key.public_key)
            logger.debug('Public key: {}'.format(_pk))
            raise
    return True


def make_raw_rrsig(sig: Signature, keys: Set[Key]) -> bytes:
    """
    Create RRSIG raw data from a bundle.

    The RRSIG wire format is described in RFC4034, section 3.1.
    """
    res = struct.pack('!HBBIIIH',
                      sig.type_covered.value,
                      sig.algorithm.value,
                      sig.labels,
                      sig.original_ttl,
                      int(sig.signature_expiration.timestamp()),
                      int(sig.signature_inception.timestamp()),
                      sig.key_tag)

    res += _dn2wire(sig.signers_name)

    prefix = _dn2wire(sig.signers_name)
    prefix += struct.pack('!HHI',
                          sig.type_covered.value,
                          _CLASS_IN,
                          sig.original_ttl,
                          )

    # Construct a list of all the keys in wire format, so that we can sort them.
    # How this should be done is described in RFC4034 (6.3).
    rdata: List[bytes] = []
    for key in keys:
        rdata += [key_to_rdata(key)]

    # Add the sorted keys, each one with the common prefix.
    for this in sorted(rdata):
        length = struct.pack('!H', len(this))
        res += prefix + length + this
    return res


def _is_rsa_key(key: Key) -> bool:
    return is_algorithm_rsa(key.algorithm)


def _dn2wire(dn: str) -> bytes:
    if dn == '.':
        return b'\00'
    raise NotImplementedError('Non-root dn2wire not implemented')


def dndepth(dn: str) -> int:
    """Return the number of DNS labels in a domain name (number of dots-1)."""
    if dn == '.':
        return 0
    raise NotImplementedError('Non-root dndepth not implemented')
