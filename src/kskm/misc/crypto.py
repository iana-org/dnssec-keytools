"""Code using the Cryptography library."""

import logging
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

from kskm.common.data import AlgorithmDNSSEC, Key
from kskm.common.ecdsa_utils import (
    ECCurve,
    KSKM_PublicKey_ECDSA,
    algorithm_to_curve,
    decode_ecdsa_public_key,
    is_algorithm_ecdsa,
)
from kskm.common.public_key import KSKM_PublicKey
from kskm.common.rsa_utils import (
    KSKM_PublicKey_RSA,
    decode_rsa_public_key,
    is_algorithm_rsa,
)

__author__ = "ft"

logger = logging.getLogger(__name__)


CryptoPubKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


def key_to_crypto_pubkey(key: Key) -> CryptoPubKey:
    """Turn a Key (DNSKEY) into a CryptoPubKey that can be used with 'cryptography'."""
    if is_algorithm_rsa(key.algorithm):
        return pubkey_to_crypto_pubkey(decode_rsa_public_key(key.public_key))
    if is_algorithm_ecdsa(key.algorithm):
        crv = algorithm_to_curve(key.algorithm)
        return pubkey_to_crypto_pubkey(decode_ecdsa_public_key(key.public_key, crv))
    raise RuntimeError(f"Can't make cryptography public key from {key}")


def pubkey_to_crypto_pubkey(pubkey: KSKM_PublicKey | None) -> CryptoPubKey:
    """Turn an KSKM_PublicKey into a CryptoPubKey."""
    if isinstance(pubkey, KSKM_PublicKey_RSA):
        return rsa_pubkey_to_crypto_pubkey(pubkey)
    if isinstance(pubkey, KSKM_PublicKey_ECDSA):
        return ecdsa_pubkey_to_crypto_pubkey(pubkey)
    raise RuntimeError(f"Can't make cryptography public key from {pubkey}")


def rsa_pubkey_to_crypto_pubkey(pubkey: KSKM_PublicKey_RSA) -> rsa.RSAPublicKey:
    """Convert an KSKM_PublicKey_RSA into a 'cryptography' rsa.RSAPublicKey."""
    rsa_n = int.from_bytes(pubkey.n, byteorder="big")
    public = rsa.RSAPublicNumbers(pubkey.exponent, rsa_n)
    return public.public_key()


def ecdsa_pubkey_to_crypto_pubkey(
    pubkey: KSKM_PublicKey_ECDSA,
) -> ec.EllipticCurvePublicKey:
    """Convert an KSKM_PublicKey_ECDSA into a 'cryptography' ec.EllipticCurvePublicKey."""
    q = pubkey.q
    curve: object
    if pubkey.curve == ECCurve.P256:
        curve = ec.SECP256R1()
        if len(q) == (256 // 8) * 2:
            # q is the bare x and y point, have to add a prefix of 0x04 (SEC 1: complete point (x,y))
            q = b"\x04" + q
    elif pubkey.curve == ECCurve.P384:
        curve = ec.SECP384R1()
        if len(q) == (384 // 8) * 2:
            # q is the bare x and y point, have to add a prefix of 0x04 (SEC 1: complete point (x,y))
            q = b"\x04" + q
    else:
        raise RuntimeError(f"Don't know which curve to use for {pubkey.curve.name}")
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, q)


def verify_signature(
    pubkey: CryptoPubKey, signature: bytes, data: bytes, algorithm: AlgorithmDNSSEC
) -> None:
    """Verify a signature over 'data' using an 'cryptography' public key."""
    _hash = _algorithm_to_hash(algorithm)
    try:
        if is_algorithm_rsa(algorithm):
            pubkey.verify(signature, data, PKCS1v15(), _hash)  # type: ignore
        elif is_algorithm_ecdsa(algorithm):
            # OpenSSL (which is at the bottom of 'cryptography' expects ECDSA signatures to
            # be in RFC3279 format (ASN.1 encoded).
            _r, _s = signature[: len(signature) // 2], signature[len(signature) // 2 :]
            r = int.from_bytes(_r, byteorder="big")
            s = int.from_bytes(_s, byteorder="big")
            signature = encode_dss_signature(r, s)
            _ec_alg = ec.ECDSA(algorithm=_algorithm_to_hash(algorithm))
            pubkey.verify(signature, data, _ec_alg)  # type: ignore
        else:
            raise RuntimeError(
                f"Don't know how to verify signature with {repr(pubkey)}"
            )
    except InvalidSignature:
        logger.warning("Validating signature failed")
        raise


def _algorithm_to_hash(alg: AlgorithmDNSSEC) -> SHA256 | SHA384:
    if alg in [AlgorithmDNSSEC.RSASHA256, AlgorithmDNSSEC.ECDSAP256SHA256]:
        return SHA256()
    if alg in [AlgorithmDNSSEC.ECDSAP384SHA384]:
        return SHA384()
    raise ValueError(f"Hashing for algorithm {alg} not supported")
