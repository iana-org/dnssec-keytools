import logging
from dataclasses import dataclass
from typing import Optional

from kskm.ksr.data import RequestBundle
from kskm.common.data import Key, FlagsDNSKEY
from kskm.common.config import KSKKey, KSKPolicy
from kskm.misc.hsm import KSKM_P11Key, KSKM_P11, get_p11_key
from kskm.common.rsa_utils import RSAPublicKeyData, public_key_to_dnssec_key
from kskm.common.validate import PolicyViolation

__author__ = 'ft'

_DNSKEY_PROTOCOL = 3

logger = logging.getLogger(__name__)


class KeyUsagePolicy_Violation(PolicyViolation):
    """ Exception raised when a key can't be used because of policy. """

    pass


@dataclass()
class CompositeKey(object):
    """Hold a key loaded from PKCS#11, and also converted to 'Key' format."""

    p11: KSKM_P11Key
    dns: Key


def load_pkcs11_key(ksk: KSKKey, p11modules: KSKM_P11, ksk_policy: KSKPolicy,
                    bundle: RequestBundle, public: bool) -> Optional[CompositeKey]:
    """
    Using a KSK key label, load that key from an HSM and then validate it is the right key and is OK to use.

    Return it as a 'CompositeKey' which is just a container representing the key in two different formats -
    the standard Key format that has all the DNSSEC related data such as TTL, and as a PKCS#11 reference
    which is used to e.g. make a signature using this key stored in an HSM.

    :param public: Ask the HSM for a public key, or not.
    """
    if ksk.valid_from > bundle.inception:
        raise KeyUsagePolicy_Violation('Key {ksk.label} is not valid at the time of bundle {bundle.id} inception')
    if ksk.valid_until is not None and ksk.valid_until < bundle.expiration:
        raise KeyUsagePolicy_Violation('Key {ksk.label} is not valid at the time of bundle {bundle.id} expiration')

    _found = get_p11_key(ksk.label, p11modules, public=public)
    if not _found:
        return None

    if isinstance(_found.public_key, RSAPublicKeyData):
        if _found.public_key.bits != ksk.rsa_size:
            raise ValueError(f'PKCS#11 key {ksk.label} is RSA-{_found.public_key.bits} - expected {ksk.rsa_size}')
        if _found.public_key.exponent != ksk.rsa_exponent:
            raise ValueError(f'PKCS#11 key {ksk.label} has RSA exponent {_found.public_key.exponent} - '
                             f'expected {ksk.rsa_exponent}')
        _key = public_key_to_dnssec_key(key=_found.public_key,
                                        key_identifier=ksk.label,
                                        algorithm=ksk.algorithm,
                                        flags=FlagsDNSKEY.SEP.value,
                                        protocol=_DNSKEY_PROTOCOL,
                                        ttl=ksk_policy.ttl,
                                        )
        return CompositeKey(p11=_found, dns=_key)
    else:
        logger.error(f'Key {ksk.label}/"{ksk.description}" for bundle {bundle.id} is not RSA')
        return None
