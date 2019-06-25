"""Code to create KeyDigest instances."""
import binascii
import logging
from hashlib import sha256

from kskm.common.config_misc import KSKKey
from kskm.common.data import Key
from kskm.common.dnssec import key_to_rdata
from kskm.common.signature import _dn2wire
from kskm.ta import DigestDNSSEC, KeyDigest

__author__ = 'ft'


logger = logging.getLogger(__name__)


def create_trustanchor_keydigest(ksk_key: KSKKey, key: Key, domain: str = '.') -> KeyDigest:
    """
    Create a TrustAnchor entry for a key in the ksrsigner configuration.

    The DS record is specified in RFC 4509.
    """
    rr = _dn2wire(domain)
    rr += key_to_rdata(key)
    logger.debug(f'Creating DS record for key {ksk_key.label} using domain + DNSKEY RDATA\n{binascii.hexlify(rr)}')
    digest = sha256(rr).digest()
    return KeyDigest(algorithm=key.algorithm,
                     digest=digest,
                     digest_type=DigestDNSSEC.SHA256,
                     id=key.key_identifier,
                     key_tag=key.key_tag,
                     valid_from=ksk_key.valid_from,
                     valid_until=ksk_key.valid_until)
