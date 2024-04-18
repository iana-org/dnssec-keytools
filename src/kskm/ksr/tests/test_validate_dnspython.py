"""
Testcode using a separate implementation of DNSSEC signature validation (dnspython).

dnspython was used to validate the implementation of signature validation, and also
to track down a bug with RDATA sorting. Thanks!
"""

import logging
import os
from pathlib import Path
from unittest import TestCase

import dns
import dns.dnssec
import dns.name
import dns.rrset
from dns.exception import ValidationFailure

from kskm.common.data import Key, Signature
from kskm.ksr import request_from_xml
from kskm.ksr.data import RequestBundle

logger = logging.getLogger(__name__)


class TestDnsPythonValidate_signatures(TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")

    def test_keysize_change_dnspython(self) -> None:
        """Test file where ZSK changed from RSA1024 to RSA2048 using dnspython"""
        self._test_file(
            "ksr-root-2016-q3-0.xml", "a6b6162e-b299-427e-b11b-1a8c54a08910"
        )

    def _test_file(self, fn: str, filter_ids: str | None = None) -> None:
        full_fn = self.data_dir.joinpath(fn)
        with open(full_fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if filter_ids and bundle.id not in filter_ids:
                continue
            try:
                dnspython_validate_bundle(bundle)
                print(f"{fn}: Bundle {bundle.id} validated successfully")
            except ValidationFailure:
                print(f"{fn}: Bundle {bundle.id} FAILED validation")
                raise


def dnspython_validate_bundle(bundle: RequestBundle) -> bool:
    """Make sure the sets of signatures and keys in a bundle is consistent"""
    # To locate keys for signatures, and to make sure all keys are covered by
    # a signature, we make a copy of the keys indexed by key_tag.
    _keys: dict[int, Key] = {}
    for key in bundle.keys:
        if key.key_tag in _keys:
            raise ValueError(
                f"More than one key with keytag {key.key_tag} in bundle {bundle.id}"
            )
        _keys[key.key_tag] = key
    if not _keys:
        raise ValueError(f"No keys in bundle {bundle.id}")

    for sig in bundle.signatures:
        if sig.key_tag not in _keys:
            raise ValueError(f"No key with key_tag {sig.key_tag} in bundle {bundle.id}")
        _keys.pop(sig.key_tag)

        try:
            res = dnspython_validate_key_sig(bundle.keys, sig)
            logger.info(f"dnspython result: {res}")
        except Exception:
            logger.exception("dnspython failed with an exception")
            raise
    if _keys:
        raise ValueError(
            f"One or more keys were not covered by a signature: {_keys.keys()}"
        )
    return True


def dnspython_validate_key_sig(keys: set[Key], sig: Signature) -> bool:
    """
    Validate that the originator of the KSR has signed all ZSKs in this bundle.

    :return: Validation outcome
    """
    res = True
    _domainname = dns.name.from_text(sig.signers_name)
    text_rdata: list[str] = []
    for key in keys:
        _dnskey = "{flags} {proto} {alg} {pkey}".format(
            flags=key.flags,
            proto=key.protocol,
            alg=key.algorithm.value,
            pkey=key.public_key.decode("ascii"),
        )
        text_rdata += [_dnskey]

    dnskey_rr = dns.rrset.from_text(
        sig.signers_name, sig.original_ttl, "IN", "DNSKEY", *text_rdata
    )
    _keys: dict[dns.name.Name, dns.rrset.RRset] = {
        _domainname: dnskey_rr,
    }

    _sigstr = "DNSKEY {alg} {label} {origttl} {sig_exp} {sig_inc} {keytag} {name} {data}".format(
        alg=sig.algorithm.value,
        label=sig.labels,
        origttl=sig.original_ttl,
        sig_exp=sig.signature_expiration.strftime("%Y%m%d%H%M%S"),
        sig_inc=sig.signature_inception.strftime("%Y%m%d%H%M%S"),
        keytag=sig.key_tag,
        name=sig.signers_name,
        data=sig.signature_data.decode("ascii"),
    )
    rrsig = dns.rrset.from_text(sig.signers_name, sig.ttl, "IN", "RRSIG", _sigstr)

    when = sig.signature_inception.timestamp()
    try:
        dns.dnssec.validate(dnskey_rr, rrsig, _keys, None, when)
    except ValidationFailure:
        res = False

    return res
