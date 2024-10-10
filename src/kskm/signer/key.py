"""PKCS#11 key interface."""

import logging

from kskm.common.config_misc import KSKKey, KSKPolicy
from kskm.common.data import FlagsDNSKEY, FrozenStrictBaseModel, Key
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.ecdsa_utils import is_algorithm_ecdsa
from kskm.common.eddsa_utils import is_algorithm_eddsa
from kskm.common.rsa_utils import KSKM_PublicKey_RSA, is_algorithm_rsa
from kskm.common.validate import PolicyViolation
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, KeyType, KSKM_P11Key, get_p11_key

__author__ = "ft"


logger = logging.getLogger(__name__)


class KeyUsagePolicy_Violation(PolicyViolation):
    """Exception raised when a key can't be used because of policy."""


class CompositeKey(FrozenStrictBaseModel):
    """Hold a key loaded from PKCS#11, and also converted to 'Key' format."""

    p11: KSKM_P11Key
    dns: Key


def load_pkcs11_key(
    ksk: KSKKey,
    p11modules: KSKM_P11,
    ksk_policy: KSKPolicy,
    bundle: RequestBundle,
    public: bool,
) -> CompositeKey | None:
    """
    Load a key from an HSM using a KSK key label and then validate it is the right key and is OK to use.

    Return it as a 'CompositeKey' which is just a container representing the key in two different formats -
    the standard Key format that has all the DNSSEC related data such as TTL, and as a PKCS#11 reference
    which is used to e.g. make a signature using this key stored in an HSM.

    :param public: Ask the HSM for a public key, or not.
    """
    if ksk.valid_from > bundle.inception:
        raise KeyUsagePolicy_Violation(
            f"Key {ksk.label} is not valid at the time of bundle {bundle.id} inception"
        )
    if ksk.valid_until is not None and ksk.valid_until < bundle.expiration:
        raise KeyUsagePolicy_Violation(
            f"Key {ksk.label} is not valid at the time of bundle {bundle.id} expiration"
        )

    _found = get_p11_key(
        ksk.label, p11modules, public=public, hash_using_hsm=ksk.hash_using_hsm
    )
    if not _found:
        return None

    if _found.public_key is None and not public:
        # Query again for the public key.
        logger.debug(
            f"Got no complimentary public key for label {ksk.label}, searching again"
        )
        _found_pub = get_p11_key(
            ksk.label, p11modules, public=True, hash_using_hsm=ksk.hash_using_hsm
        )
        if _found_pub:
            _found = _found.replace(public_key=_found_pub.public_key)

    if not _found.public_key:
        logger.error(
            f"Loaded private key for label {ksk.label}, but could not load public key"
        )
        return None

    match _found.key_type:
        case KeyType.RSA:
            if not is_algorithm_rsa(ksk.algorithm):
                raise ValueError(
                    f"PKCS#11 key {_found.label} is an RSA key, expected {ksk.algorithm.name}"
                )
            pubkey = KSKM_PublicKey_RSA.decode_public_key(
                _found.public_key, ksk.algorithm
            )
            if pubkey.bits != ksk.rsa_size:
                raise ValueError(
                    f"PKCS#11 key {_found.label} is RSA-{pubkey.bits} - expected {ksk.rsa_size}"
                )
            if pubkey.exponent != ksk.rsa_exponent:
                raise ValueError(
                    f"PKCS#11 key {_found.label} has RSA exponent {pubkey.exponent} - "
                    f"expected {ksk.rsa_exponent}"
                )
        case KeyType.EC:
            if not is_algorithm_ecdsa(ksk.algorithm) and not is_algorithm_eddsa(
                ksk.algorithm
            ):
                raise ValueError(
                    f"PKCS#11 key {_found.label} is an ECDSA/EdDSA key, expected {ksk.algorithm.name}"
                )
        case _:
            logger.error(
                f'Key "{ksk.label}/{ksk.description}" for bundle {bundle.id} found in PKCS#11, but not recognised'
            )
            logger.debug(f"Key {ksk.label}: {_found}")
            return None

    _key = public_key_to_dnssec_key(
        public_key=_found.public_key,
        key_identifier=ksk.label,
        algorithm=ksk.algorithm,
        flags=FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value,
        ttl=ksk_policy.ttl,
    )
    return CompositeKey(p11=_found, dns=_key)
