from __future__ import annotations

import logging
from copy import copy
from dataclasses import asdict, dataclass, field
from typing import Mapping, Optional, Type, cast

from kskm.common.rsa_utils import KSKM_PublicKey_RSA
from kskm.keymaster.common import get_session
from kskm.keymaster.keygen import private_key_template, public_key_template
from kskm.misc.hsm import KSKM_P11, KeyType, get_p11_key, get_p11_secret_key

__author__ = 'ft'

logger = logging.getLogger(__name__)


@dataclass
class WrappedKey(object):
    key_label: str
    key_type: KeyType
    public_wrapped: Optional[bytes] = field(repr=False)
    private_wrapped: Optional[bytes] = field(repr=False)
    wrap_key_label: str

    def to_dict(self) -> dict:
        res = asdict(self)
        res['key_type'] = res['key_type'].name
        return res

    @classmethod
    def from_dict(cls: Type[WrappedKey], data: Mapping) -> WrappedKey:
        _data = dict(copy(data))  # do not modify caller's data
        if 'key_type' in data:
            _data['key_type'] = KeyType[data['key_type']]
        return cls(**_data)


@dataclass
class WrappedKeyRSA(WrappedKey):
    bits: int
    exponent: int
    modulus: bytes = field(repr=False)


def key_backup(label: str, wrap_label: str, p11modules: KSKM_P11) -> Optional[WrappedKey]:
    wrap_key = get_p11_secret_key(wrap_label, p11modules)
    if not wrap_key:
        logger.error(f'No secret key with label {repr(wrap_label)} found')
        return None

    existing_key = get_p11_key(label, p11modules, public=False)
    if not existing_key:
        logger.error(f'No key with label {label} found')
        return None

    logger.info(f'Backing up key {existing_key} using wrapping key {wrap_key}')
    session = get_session(p11modules, logger)

    if not wrap_key.privkey_handle:
        raise RuntimeError('Wrapping key has no private key')
    private_wrapped = None
    public_wrapped = None
    if wrap_key.privkey_handle and existing_key.privkey_handle:
        _wrap = session.wrapKey(cast(int, wrap_key.privkey_handle[0]),
                                cast(int, existing_key.privkey_handle[0]),
                                mecha=wrap_key.key_wrap_mechanism())
        private_wrapped = bytes(_wrap)
    if wrap_key.privkey_handle and existing_key.pubkey_handle:
        _wrap = session.wrapKey(cast(int, wrap_key.privkey_handle[0]),
                                cast(int, existing_key.pubkey_handle[0]),
                                mecha=wrap_key.key_wrap_mechanism())
        public_wrapped = bytes(_wrap)
    if existing_key.key_type == KeyType.RSA and isinstance(existing_key.public_key, KSKM_PublicKey_RSA):
        return WrappedKeyRSA(key_label=existing_key.label,
                             key_type=existing_key.key_type,
                             wrap_key_label=wrap_key.label,
                             private_wrapped=private_wrapped,
                             public_wrapped=public_wrapped,
                             bits=existing_key.public_key.bits,
                             exponent=existing_key.public_key.exponent,
                             modulus=existing_key.public_key.n,
                             )
    raise RuntimeError(f'Can\'t create WrappedKey from {existing_key}')


def key_restore(wrapped_key: WrappedKey, p11modules: KSKM_P11) -> bool:
    unwrap_key = get_p11_secret_key(wrapped_key.wrap_key_label, p11modules)
    if not unwrap_key:
        logger.error(f'No secret key with label {repr(wrapped_key.wrap_key_label)} found')
        return False

    existing_key = get_p11_key(wrapped_key.key_label, p11modules, public=False)
    if existing_key:
        logger.error(f'A key with label {wrapped_key.key_label} already exists')
        return False

    logger.info(f'Restoring key {wrapped_key.key_label} using wrapping key {unwrap_key}')
    session = get_session(p11modules, logger)

    if not unwrap_key.privkey_handle:
        raise RuntimeError('Unwrapping key has no private key')
    
    privateKeyTemplate = private_key_template(wrapped_key.key_label, wrapped_key.key_type.value)
    res = session.unwrapKey(unwrap_key.privkey_handle[0], wrapped_key.private_wrapped, privateKeyTemplate,
                            mecha=unwrap_key.key_wrap_mechanism())
    logger.debug(f'Private key unwrap result: {res}')

    if isinstance(wrapped_key, WrappedKeyRSA):
        publicKeyTemplate = public_key_template(wrapped_key.key_label, wrapped_key.key_type.value,
                                                rsa_exponent=wrapped_key.exponent,
                                                rsa_modulus=wrapped_key.modulus)
    else:
        raise RuntimeError(f'Can\'t get a public key template for {wrapped_key}')
    res = session.createObject(publicKeyTemplate)
    logger.debug(f'Public key createObject result: {res}')

    logger.info(f'Unwrapped key {wrapped_key}')
    return True
