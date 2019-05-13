import base64
import logging
import time
from typing import List, Optional

from PyKCS11 import Mechanism
from PyKCS11.LowLevel import CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, \
    CKA_MODULUS_BITS, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VERIFY, \
    CKA_WRAP, CKK_AES, CKK_DES3, CKK_RSA, CKM_AES_KEY_GEN, CKM_DES3_KEY_GEN, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, \
    CKO_SECRET_KEY, CK_FALSE, CK_TRUE, CKA_VALUE_LEN

from kskm.common.data import FlagsDNSKEY
from kskm.keymaster.common import get_session
from kskm.misc.hsm import KSKM_P11, KSKM_P11Key, get_p11_key, get_p11_secret_key

__author__ = 'ft'


logger = logging.getLogger(__name__)


def generate_key_label(flags: int, now: Optional[int] = None) -> str:
    """
    Generate CKA_LABEL monotonically from current time.

    A comment from the previous code base:

    CKA_LABEL HACK
    AEP Keyper can only display 7 characters and cannot change the HSM internal CKA_LABEL once created.
    So, we label them with a monotonically increasing string based on seconds since epoch.
    """
    if now is None:
        now = int(time.time())

    _b64data = base64.b32encode(now.to_bytes(length=4, byteorder='big')).lower()
    data = _b64data[:6].decode('utf-8') # six characters time, plus prefix character below

    if flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value:
        return 'K' + data
    if flags == FlagsDNSKEY.ZONE:
        return 'Z' + data
    if flags == 0:
        return 'C' + data
    return 'U' + data


def generate_wrapping_key(label: str, algorithm: str, p11modules: KSKM_P11) -> None:
    """Generate a SECRET (wrapping) key (3DES)."""
    template = [
        (CKA_LABEL,       label),
        (CKA_CLASS,       CKO_SECRET_KEY),
        (CKA_TOKEN,       CK_TRUE),
        (CKA_ENCRYPT,     CK_TRUE),
        (CKA_DECRYPT,     CK_TRUE),
        (CKA_WRAP,        CK_TRUE),
        (CKA_UNWRAP,      CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
    ]
    if algorithm == 'AES256':
        _mech = Mechanism(CKM_AES_KEY_GEN, None)
        template += [(CKA_KEY_TYPE, CKK_AES),
                     (CKA_VALUE_LEN, 256 // 8),
                     ]
    elif algorithm == '3DES':
        _mech = Mechanism(CKM_DES3_KEY_GEN, None)
        template += [(CKA_KEY_TYPE, CKK_DES3)]
    else:
        raise RuntimeError(f'Unknown wrapping algorithm: {algorithm}')

    existing_key = get_p11_secret_key(label, p11modules)
    if existing_key:
        logger.error(f'A secret key with label {repr(label)} already exists: {existing_key}')
        return None

    session = get_session(p11modules, logger)
    logger.debug(f'Generating secret key using session {session}')
    session.generateKey(template, _mech)
    new_key = get_p11_secret_key(label, p11modules)
    logger.info(f'Generated key: {new_key}')


def generate_rsa_key(flags: int, bits: int, p11modules: KSKM_P11, exponent: int = 65537) -> Optional[KSKM_P11Key]:
    if exponent == 65537:
        # TODO: don't use hard-coded value perhaps?
        exponent_tuple = (0x01, 0x00, 0x01)
    else:
        raise RuntimeError(f'RSA exponent {exponent} not allowed')

    label = generate_key_label(flags)

    publicKeyTemplate = [
        (CKA_LABEL,           label),
        #(CKA_ID,              (0x0,)),
        (CKA_CLASS,           CKO_PUBLIC_KEY),
        (CKA_KEY_TYPE,        CKK_RSA),
        (CKA_TOKEN,           CK_TRUE),  # True if put in HSM
        (CKA_ENCRYPT,         CK_TRUE),
        (CKA_VERIFY,          CK_TRUE),
        #(CKA_EXTRACTABLE,     CK_TRUE),  # SoftHSMv2 doesn't allow this in the public key template
        (CKA_WRAP,            CK_FALSE),
        (CKA_MODULUS_BITS,    bits),
        (CKA_PUBLIC_EXPONENT, exponent_tuple)
    ]

    privateKeyTemplate = [
        (CKA_LABEL,       label),
        #(CKA_ID,          (0x0,)),
        (CKA_CLASS,       CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE,    CKK_RSA),
        (CKA_TOKEN,       CK_TRUE),   # True if put in HSM
        (CKA_DECRYPT,     CK_TRUE),
        (CKA_SIGN,        CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),   # if API EXPORT enabled
        (CKA_UNWRAP,      CK_FALSE),
        (CKA_DERIVE,      CK_FALSE),  # was true - ensure FIPS mode
        (CKA_SENSITIVE,   CK_TRUE),
        (CKA_PRIVATE,     CK_TRUE),
    ]

    return generate_key_from_templates(publicKeyTemplate, privateKeyTemplate, label, p11modules)


def generate_ec_key(flags: int, curve: str, p11modules: KSKM_P11) -> Optional[KSKM_P11Key]:
    raise NotImplementedError('EC key generation not implemented yet')


def generate_key_from_templates(publicKeyTemplate: List, privateKeyTemplate: List,
                                label: str, p11modules: KSKM_P11) -> Optional[KSKM_P11Key]:
    """Generate a key pair using C_GenerateKeyPair."""
    # Check that a key with that label does not already exist
    existing_key = get_p11_key(label, p11modules, public=True)
    if existing_key:
        logger.error(f'A key with label {label} already exists: {existing_key}')
        # Since the AEP Keyper only displays 7 characters, we truncate the
        # monotonically increasing value (current time) to 6 characters of base32
        # output. That means the last character changes every four seconds, so to
        # give a retry a good chance of being unique, we sleep four seconds here.
        time.sleep(4)
        return None

    session = get_session(p11modules, logger)
    logger.debug(f'Generating key using session {session}')
    session.generateKeyPair(publicKeyTemplate, privateKeyTemplate)
    new_key = get_p11_key(label, p11modules, public=True)
    logger.info(f'Generated key: {new_key}')
    return new_key
