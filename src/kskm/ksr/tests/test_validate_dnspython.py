"""
Testcode using a separate implementation of DNSSEC signature validation (dnspython).

dnspython was used to validate the implementation of signature validation, and also
to track down a bug with RDATA sorting. Thanks!
"""
import logging
import os
from typing import Set
from unittest import TestCase

import dns
import dns.rrset
import pkg_resources
from dns.dnssec import ValidationFailure

from kskm.common.data import Key, Signature
from kskm.ksr import request_from_xml
from kskm.ksr.data import RequestBundle

logger = logging.getLogger(__name__)


class TestDnsPythonValidate_signatures(TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')

    def test_keysize_change_dnspython(self):
        """ Test file where ZSK changed from RSA1024 to RSA2048 using dnspython """
        self._test_file('ksr-root-2016-q3-0.xml', 'a6b6162e-b299-427e-b11b-1a8c54a08910')

    def _test_file(self, fn, filter=None):
        fn = os.path.join(self.data_dir, fn)
        with open(fn, 'r') as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if filter and bundle.id not in filter:
                continue
            try:
                dnspython_validate_bundle(bundle)
                print('{}: Bundle {} validated successfully'.format(fn, bundle.id))
            except ValidationFailure:
                print('{}: Bundle {} FAILED validation'.format(fn, bundle.id))
                raise


def dnspython_validate_bundle(bundle: RequestBundle) -> bool:
    """ Make sure the sets of signatures and keys in a bundle is consistent """
    # To locate keys for signatures, and to make sure all keys are covered by
    # a signature, we make a copy of the keys indexed by key_tag.
    _keys = {}
    for key in bundle.keys:
        if key.key_tag in _keys:
            raise ValueError('More than one key with keytag {} in bundle {}'.format(key.key_tag, bundle.id))
        _keys[key.key_tag] = key
    if not _keys:
        raise ValueError('No keys in bundle {}'.format(bundle.id))

    for sig in bundle.signatures:
        if sig.key_tag not in _keys:
            raise ValueError('No key with key_tag {} in bundle {}'.format(sig.keytag, bundle.id))
        _keys.pop(sig.key_tag)

        try:
            res = dnspython_validate_key_sig(bundle.keys, sig)
            logger.info('dnspython result: {}'.format(res))
        except Exception:
            logger.exception('dnspython failed with an exception')
            raise
    if _keys:
        raise ValueError('One or more keys were not covered by a signature: {}'.format(_keys.keys()))
    return True


def dnspython_validate_key_sig(keys: Set[Key], sig: Signature) -> bool:
    """
    Validate that the originator of the KSR has signed all ZSKs in this bundle.

    :return: Validation outcome
    """
    res = True
    _domainname = dns.name.from_text(sig.signers_name)
    text_rdata = []
    for key in keys:
        _dnskey = '{flags} {proto} {alg} {pkey}'.format(flags=key.flags,
                                                        proto=key.protocol,
                                                        alg=key.algorithm.value,
                                                        pkey=key.public_key.decode('ascii'),
                                                        )
        text_rdata += [_dnskey]

    dnskey_rr = dns.rrset.from_text(sig.signers_name, sig.original_ttl, 'IN', 'DNSKEY', *text_rdata)
    _keys = {
        _domainname: dnskey_rr,
    }

    _sigstr = 'DNSKEY {alg} {label} {origttl} {sig_exp} {sig_inc} {keytag} {name} {data}'.format(
        alg=sig.algorithm.value,
        label=sig.labels,
        origttl=sig.original_ttl,
        sig_exp=sig.signature_expiration.strftime('%Y%m%d%H%M%S'),
        sig_inc=sig.signature_inception.strftime('%Y%m%d%H%M%S'),
        keytag=sig.key_tag,
        name=sig.signers_name,
        data=sig.signature_data.decode('ascii'),
    )
    rrsig = dns.rrset.from_text(sig.signers_name, sig.ttl, 'IN', 'RRSIG', _sigstr)

    when = sig.signature_inception.timestamp()
    try:
        dns.dnssec.validate(dnskey_rr, rrsig, _keys, None, when)
    except ValidationFailure:
        res = False

    return res
