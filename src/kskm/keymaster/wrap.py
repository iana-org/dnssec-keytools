import logging
from typing import Optional

from PyKCS11 import Mechanism
from PyKCS11.LowLevel import CKK_RSA, CKM_AES_KEY_WRAP, CKM_DES3_ECB

from kskm.keymaster.common import get_session
from kskm.keymaster.keygen import private_key_template
from kskm.misc.hsm import KSKM_P11, get_p11_key, get_p11_secret_key

__author__ = 'ft'

logger = logging.getLogger(__name__)


def key_backup(label: str, wrap_label: str, algorithm: str, p11modules: KSKM_P11) -> Optional[bytes]:
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

    if algorithm == 'AES256':
        _mech = Mechanism(CKM_AES_KEY_WRAP, None)
    elif algorithm == '3DES':
        _mech = Mechanism(CKM_DES3_ECB, None)
    else:
        raise RuntimeError(f'Unknown wrapping algorithm: {algorithm}')

    if not wrap_key.private_key:
        raise RuntimeError('Wrapping key has no private key ')
    res = session.wrapKey(wrap_key.private_key[0], existing_key.private_key[0], mecha=_mech)
    #logger.debug(f'Wrap result: {res}')
    return bytes(res)


def key_restore(wrapped_key: bytes, label: str, unwrap_label: str, algorithm: str, p11modules: KSKM_P11) -> bool:
    unwrap_key = get_p11_secret_key(unwrap_label, p11modules)
    if not unwrap_key:
        logger.error(f'No secret key with label {repr(unwrap_label)} found')
        return False

    existing_key = get_p11_key(label, p11modules, public=False)
    if existing_key:
        logger.error(f'A key with label {label} already exists')
        return False

    logger.info(f'Restoring key {label} using wrapping key {unwrap_key}')
    session = get_session(p11modules, logger)

    if algorithm == 'AES256':
        _mech = Mechanism(CKM_AES_KEY_WRAP, None)
    elif algorithm == '3DES':
        _mech = Mechanism(CKM_DES3_ECB, None)
    else:
        raise RuntimeError(f'Unknown wrapping algorithm: {algorithm}')

    if not unwrap_key.private_key:
        raise RuntimeError('Unwrapping key has no private key ')
    
    privateKeyTemplate = private_key_template(label, CKK_RSA)
    res = session.unwrapKey(unwrap_key.private_key[0], wrapped_key, privateKeyTemplate, mecha=_mech)
    logger.debug(f'Unwrap result: {res}')
    return True
