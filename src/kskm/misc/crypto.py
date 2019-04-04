"""Code using the Cryptography library."""
import logging

from kskm.common.data import Key, AlgorithmDNSSEC
from kskm.common.rsa_utils import decode_rsa_public_key, RSAPublicKeyData

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from cryptography.exceptions import InvalidSignature


__author__ = 'ft'

logger = logging.getLogger(__name__)


def key_to_crypto_pubkey(key: Key) -> rsa.RSAPublicKey:
    pubkey = decode_rsa_public_key(key.public_key)
    return rsapubkey_to_crypto_pubkey(pubkey)


def rsapubkey_to_crypto_pubkey(pubkey: RSAPublicKeyData) -> rsa.RSAPublicKey:
    rsa_n = int.from_bytes(pubkey.n, byteorder='big')
    public = rsa.RSAPublicNumbers(pubkey.exponent, rsa_n)
    return default_backend().load_rsa_public_numbers(public)


def verify_signature(pubkey: rsa.RSAPublicKey, signature: bytes, data: bytes, algorithm: AlgorithmDNSSEC) -> None:
    _hash = _algorithm_to_hash(algorithm)
    try:
        pubkey.verify(signature, data, PKCS1v15(), _hash)
    except InvalidSignature:
        logger.warning('Validating RSA signature failed')
        raise


def _algorithm_to_hash(alg: AlgorithmDNSSEC) -> SHA256:
    if alg in [AlgorithmDNSSEC.RSASHA256, AlgorithmDNSSEC.ECDSAP256SHA256]:
        return SHA256()
    raise ValueError('Hashing for algorithm {} not supported'.format(alg))
