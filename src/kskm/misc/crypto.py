"""Code using the Cryptography library."""

import logging
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import \
    encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

from kskm.common.data import AlgorithmDNSSEC, Key
from kskm.common.public_key import KSKM_PublicKeyType
from kskm.common.ecdsa_utils import (KSKM_PublicKey_ECDSA,
                                     decode_ecdsa_public_key,
                                     is_algorithm_ecdsa)
from kskm.common.rsa_utils import (KSKM_PublicKey_RSA, decode_rsa_public_key,
                                   is_algorithm_rsa)

__author__ = 'ft'

logger = logging.getLogger(__name__)


CryptoPubKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


def key_to_crypto_pubkey(key: Key) -> rsa.RSAPublicKey:
    if is_algorithm_rsa(key.algorithm):
        return pubkey_to_crypto_pubkey(decode_rsa_public_key(key.public_key))
    elif is_algorithm_ecdsa(key.algorithm):
        return pubkey_to_crypto_pubkey(decode_ecdsa_public_key(key.public_key, key.algorithm))
    raise RuntimeError(f"Can't make cryptography public key from {key}")


def pubkey_to_crypto_pubkey(pubkey: Optional[KSKM_PublicKeyType]) -> CryptoPubKey:
    if isinstance(pubkey, KSKM_PublicKey_RSA):
        return rsa_pubkey_to_crypto_pubkey(pubkey)
    elif isinstance(pubkey, KSKM_PublicKey_ECDSA):
        return ecdsa_pubkey_to_crypto_pubkey(pubkey)
    else:
        raise RuntimeError(f"Can't make cryptography public key from {pubkey}")


def rsa_pubkey_to_crypto_pubkey(pubkey: KSKM_PublicKey_RSA) -> rsa.RSAPublicKey:
    rsa_n = int.from_bytes(pubkey.n, byteorder='big')
    public = rsa.RSAPublicNumbers(pubkey.exponent, rsa_n)
    return default_backend().load_rsa_public_numbers(public)


def ecdsa_pubkey_to_crypto_pubkey(pubkey: KSKM_PublicKey_ECDSA) -> ec.EllipticCurvePublicKey:
    if pubkey.algorithm == AlgorithmDNSSEC.ECDSAP256SHA256:
        curve = ec.SECP256R1()
    elif pubkey.algorithm == AlgorithmDNSSEC.ECDSAP384SHA384:
        curve = ec.SECP384R1()
    else:
        raise RuntimeError(f"Don't know which curve to use for {pubkey.algorithm.name}")
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, pubkey.q)


def verify_signature(pubkey: CryptoPubKey, signature: bytes, data: bytes, algorithm: AlgorithmDNSSEC) -> None:
    _hash = _algorithm_to_hash(algorithm)
    try:
        if is_algorithm_rsa(algorithm):
            pubkey.verify(signature, data, PKCS1v15(), _hash)
        elif is_algorithm_ecdsa(algorithm):
            # OpenSSL (which is at the bottom of 'cryptography' expects ECDSA signatures to
            # be in RFC3279 format (ASN.1 encoded).
            _r, _s = signature[:len(signature) // 2], signature[len(signature) // 2:]
            r = int.from_bytes(_r, byteorder='big')
            s = int.from_bytes(_s, byteorder='big')
            signature = encode_dss_signature(r, s)
            _ec_alg = ec.ECDSA(algorithm=_algorithm_to_hash(algorithm))
            pubkey.verify(signature, data, _ec_alg)
        else:
            raise RuntimeError(f"Don't know how to verify signature with {repr(pubkey)}")
    except InvalidSignature:
        logger.warning('Validating signature failed')
        raise


def _algorithm_to_hash(alg: AlgorithmDNSSEC) -> Union[SHA256, SHA384]:
    if alg in [AlgorithmDNSSEC.RSASHA256, AlgorithmDNSSEC.ECDSAP256SHA256]:
        return SHA256()
    if alg in [AlgorithmDNSSEC.ECDSAP384SHA384]:
        return SHA384()
    raise ValueError(f'Hashing for algorithm {alg} not supported')
