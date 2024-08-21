"""Key generation functions."""

import base64
import logging
import math
import time
from typing import Any

from PyKCS11.LowLevel import (
    CK_FALSE,
    CK_TRUE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
)

from kskm.common.data import FlagsDNSKEY
from kskm.common.ecdsa_utils import ECCurve
from kskm.keymaster.common import get_session
from kskm.misc.hsm import KSKM_P11, KSKM_P11Key, get_p11_key

__author__ = "ft"


logger = logging.getLogger(__name__)


def generate_key_label(flags: int, now: int | None = None) -> str:
    """
    Generate CKA_LABEL monotonically from current time.

    A comment from the previous code base:

    CKA_LABEL HACK
    AEP Keyper can only display 7 characters and cannot change the HSM internal CKA_LABEL once created.
    So, we label them with a monotonically increasing string based on seconds since epoch.
    """
    if now is None:
        now = int(time.time())

    _b64data = base64.b32encode(now.to_bytes(length=4, byteorder="big")).lower()
    data = _b64data[:6].decode(
        "utf-8"
    )  # six characters time, plus prefix character below

    if flags == FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value:
        return "K" + data
    if flags == FlagsDNSKEY.ZONE:
        return "Z" + data
    if flags == 0:
        return "C" + data
    return "U" + data


def generate_rsa_key(
    flags: int,
    bits: int,
    p11modules: KSKM_P11,
    exponent: int = 65537,
    label: str | None = None,
) -> KSKM_P11Key | None:
    """Generate RSA key."""
    if label is None:
        label = generate_key_label(flags)

    publicKeyTemplate = public_key_template(
        label, CKK_RSA, bits=bits, rsa_exponent=exponent
    )
    privateKeyTemplate = private_key_template(label, CKK_RSA)

    return generate_key_from_templates(
        publicKeyTemplate, privateKeyTemplate, label, p11modules
    )


def public_key_template(
    label: str,
    key_type: int,
    bits: int | None = None,
    rsa_exponent: int | None = None,
    rsa_modulus: bytes | None = None,
) -> list[tuple[Any, Any]]:
    """Return a template used when generating public keys."""
    publicKeyTemplate: list[tuple[Any, ...]] = [
        (CKA_LABEL, label),
        # (CKA_ID,              (0x0,)),
        (CKA_CLASS, CKO_PUBLIC_KEY),
        (CKA_KEY_TYPE, key_type),
        (CKA_TOKEN, CK_TRUE),  # True if put in HSM
        (CKA_ENCRYPT, CK_TRUE),
        (CKA_VERIFY, CK_TRUE),
        # (CKA_EXTRACTABLE,     CK_TRUE),  # SoftHSMv2 doesn't allow this in the public key template
        (CKA_WRAP, CK_FALSE),
    ]
    if bits is not None:
        publicKeyTemplate += [(CKA_MODULUS_BITS, bits)]
    if rsa_exponent is not None:
        _exp_len = math.ceil(int.bit_length(rsa_exponent) / 8)
        _exp = int.to_bytes(rsa_exponent, length=_exp_len, byteorder="big")
        exponent_tuple = tuple(_exp)
        publicKeyTemplate += [(CKA_PUBLIC_EXPONENT, exponent_tuple)]
    if rsa_modulus is not None:
        publicKeyTemplate += [(CKA_MODULUS, rsa_modulus)]

    return publicKeyTemplate


def private_key_template(label: str, key_type: int) -> list[tuple[Any, Any]]:
    """Return a template used when generating or unwrapping private keys."""
    privateKeyTemplate: list[tuple[Any, Any]] = [
        (CKA_LABEL, label),
        # (CKA_ID,          (0x0,)),
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE, key_type),
        (CKA_TOKEN, CK_TRUE),  # True if put in HSM
        (CKA_DECRYPT, CK_TRUE),
        (CKA_SIGN, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),  # if API EXPORT enabled
        (CKA_UNWRAP, CK_FALSE),
        (CKA_DERIVE, CK_FALSE),  # was true - ensure FIPS mode
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_PRIVATE, CK_TRUE),
    ]
    return privateKeyTemplate


def generate_ec_key(
    flags: int, curve: ECCurve, p11modules: KSKM_P11, label: str | None = None
) -> KSKM_P11Key | None:
    """Generate EC key."""
    raise NotImplementedError("EC key generation not implemented yet")


def generate_key_from_templates(
    publicKeyTemplate: list[tuple[Any, Any]],
    privateKeyTemplate: list[tuple[Any, Any]],
    label: str,
    p11modules: KSKM_P11,
) -> KSKM_P11Key | None:
    """Generate a key pair using C_GenerateKeyPair."""
    # Check that a key with that label does not already exist
    existing_key = get_p11_key(label, p11modules, public=True)
    if existing_key:
        logger.error(f"A key with label {label} already exists: {existing_key}")
        # Since the AEP Keyper only displays 7 characters, we truncate the
        # monotonically increasing value (current time) to 6 characters of base32
        # output. That means the last character changes every four seconds, so to
        # give a retry a good chance of being unique, we sleep four seconds here.
        time.sleep(4)
        return None

    session = get_session(p11modules, logger)
    logger.debug(f"Generating key using session {session}")
    session.generateKeyPair(publicKeyTemplate, privateKeyTemplate)
    new_key = get_p11_key(label, p11modules, public=True)
    logger.info(f"Generated key: {new_key}")
    return new_key
