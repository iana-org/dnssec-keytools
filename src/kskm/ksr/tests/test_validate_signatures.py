import base64
import os
from unittest import TestCase

import pkg_resources
from cryptography.exceptions import InvalidSignature

from kskm.common.data import AlgorithmDNSSEC, Key, Signature
from kskm.common.signature import validate_signatures
from kskm.ksr import request_from_xml
from kskm.ksr.data import RequestBundle


class TestValidate_signatures(TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = pkg_resources.resource_filename(__name__, "data")

    def test_validate_ksk_proof_of_ownership_1(self) -> None:
        """Validate ZSK proof of ownership in ksr-root-2009-q4-2.xml"""
        self._test_file("ksr-root-2009-q4-2.xml")

    def test_validate_ksk_proof_of_ownership_2(self) -> None:
        """Validate ZSK proof of ownership in ksr-root-2010-q1-0.xml"""
        self._test_file("ksr-root-2010-q1-0.xml")

    def test_validate_ksk_proof_of_ownership_3(self) -> None:
        """Validate ZSK proof of ownership in ksr-root-2010-q2-0.xml"""
        self._test_file("ksr-root-2010-q2-0.xml")

    def test_validate_ksk_proof_of_ownership_4(self) -> None:
        """Validate ZSK proof of ownership in ksr-root-2010-q2-0.xml"""
        self._test_file("ksr-root-2016-q3-0.xml")

    def test_keysize_change(self) -> None:
        """Test file where ZSK changed from RSA1024 to RSA2048"""
        # This bundle used to trigger a bug in the RDATA sorting before hashing
        self._test_file(
            "ksr-root-2016-q3-0.xml",
            filter_ids=["a6b6162e-b299-427e-b11b-1a8c54a08910"],
        )

    def test_invalid_signature(self) -> None:
        """Change a key to break the signature"""
        bundle = self._load_bundle_from_file(
            "ksr-root-2016-q3-0.xml", "a6b6162e-b299-427e-b11b-1a8c54a08910"
        )
        assert bundle is not None
        # validate signature is OK with the original key
        self.assertTrue(validate_signatures(bundle))
        key = bundle.keys.pop()
        _pk = base64.b64decode(key.public_key)
        # change the last byte of the public key
        _pk = _pk[:-1] + bytes([_pk[-1] + 1])
        new_key = Key(
            algorithm=key.algorithm,
            flags=key.flags,
            key_identifier=key.key_identifier,
            key_tag=key.key_tag,
            protocol=key.protocol,
            public_key=base64.b64encode(_pk),
            ttl=key.ttl,
        )
        bundle.keys.add(new_key)
        # test that the signature no longer validates
        with self.assertRaises(InvalidSignature):
            validate_signatures(bundle)

    def test_key_without_signature(self) -> None:
        """Add a key without a signature"""
        bundle = self._load_bundle_from_file(
            "ksr-root-2016-q3-0.xml", "a6b6162e-b299-427e-b11b-1a8c54a08910"
        )
        assert bundle is not None
        new_key = Key(
            key_identifier="ZSK-24315",
            key_tag=24315,
            ttl=1978,
            flags=256,
            protocol=3,
            algorithm=AlgorithmDNSSEC.RSASHA1,
            public_key=base64.b64encode(b"test key"),
        )
        bundle.keys.add(new_key)
        # test that the signature no longer validates
        with self.assertRaises(InvalidSignature):
            validate_signatures(bundle)

    def test_signature_without_key(self) -> None:
        """Add a key without a signature"""
        bundle = self._load_bundle_from_file(
            "ksr-root-2016-q3-0.xml", "a6b6162e-b299-427e-b11b-1a8c54a08910"
        )
        assert bundle is not None
        _sig = list(bundle.signatures)[0]
        new_sig = Signature(
            key_identifier="test id",
            ttl=_sig.ttl,
            type_covered=_sig.type_covered,
            algorithm=_sig.algorithm,
            labels=_sig.labels,
            original_ttl=_sig.original_ttl,
            signature_expiration=_sig.signature_expiration,
            signature_inception=_sig.signature_inception,
            key_tag=1234,
            signers_name=_sig.signers_name,
            signature_data=_sig.signature_data,
        )
        bundle.signatures.add(new_sig)
        # test that the signature no longer validates
        with self.assertRaises(ValueError):
            validate_signatures(bundle)

    def test_duplicate_key_identifier(self) -> None:
        """Add a key with the same key_identifier as another key in the set"""
        bundle = self._load_bundle_from_file(
            "ksr-root-2016-q3-0.xml", "a6b6162e-b299-427e-b11b-1a8c54a08910"
        )
        assert bundle is not None
        new_key = Key(
            key_identifier=list(bundle.keys)[0].key_identifier,
            key_tag=4711,
            ttl=1978,
            flags=256,
            protocol=3,
            algorithm=AlgorithmDNSSEC.RSASHA1,
            public_key=base64.b64encode(b"test key"),
        )
        bundle.keys.add(new_key)
        # test that the signature no longer validates
        with self.assertRaises(ValueError):
            validate_signatures(bundle)

    def _load_bundle_from_file(self, fn: str, bundle_id: str) -> RequestBundle | None:
        fn = os.path.join(self.data_dir, fn)
        with open(fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if bundle.id == bundle_id:
                return bundle
        return None

    def _test_file(self, fn: str, filter_ids: list[str] | None = None) -> None:
        fn = os.path.join(self.data_dir, fn)
        with open(fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if filter_ids and bundle.id not in filter_ids:
                continue
            try:
                validate_signatures(bundle)
                print(f"{fn}: Bundle {bundle.id} validated successfully")
            except InvalidSignature:
                print(f"{fn}: Bundle {bundle.id} FAILED validation")
                raise
