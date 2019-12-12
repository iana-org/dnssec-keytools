import base64
import datetime
import os
import unittest
from dataclasses import replace
from typing import Optional

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmDNSSEC
from kskm.ksr import load_ksr, request_from_xml
from kskm.ksr.validate import validate_request
from kskm.ksr.verify_bundles import KSR_BUNDLE_COUNT_Violation, KSR_BUNDLE_KEYS_Violation, KSR_BUNDLE_POP_Violation, \
    KSR_BUNDLE_UNIQUE_Violation
from kskm.ksr.verify_header import KSR_DOMAIN_Violation
from kskm.ksr.verify_policy import KSR_POLICY_ALG_Violation, KSR_PolicyViolation


class Test_Validate_KSR(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')
        self.policy_fn = os.path.join(self.data_dir, 'response_policy.yaml')

    def test_validate_ksr_with_invalid_signature(self):
        """ Test manipulating KSR signature """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle signature expire in the past
        _signature_check_expire_horizon = False
        policy = RequestPolicy(warn_instead_of_fail=False,
                               signature_check_expire_horizon=_signature_check_expire_horizon,
                               )
        ksr = load_ksr(fn, policy)

        # The request was successfully validated in load_ksr, now manipulate it
        first_bundle = ksr.bundles[0]
        sig = first_bundle.signatures.pop()
        # change the last byte of the signature
        sig_data = base64.b64decode(sig.signature_data)
        sig_data = sig_data[:-1] + b'\x00' if sig_data[-1] else b'\x01'
        # put everything back into the ksr
        sig = replace(sig, signature_data=base64.b64encode(sig_data))
        first_bundle.signatures.add(sig)
        ksr.bundles[0] = first_bundle

        # Now try and verify the KSR again and ensure it fails signature validation
        with self.assertRaises(KSR_BUNDLE_POP_Violation):
            validate_request(ksr, policy)

        # Test that the invalid KSR is accepted with signature validations turned off
        validate_request(ksr, replace(policy, validate_signatures=False))

    def test_validate_ksr_with_invalid_keys(self):
        """ Test manipulating KSR keys """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle signature expire in the past
        _signature_check_expire_horizon = False
        policy = RequestPolicy(warn_instead_of_fail=False,
                               signature_check_expire_horizon=_signature_check_expire_horizon,
                               )
        ksr = load_ksr(fn, policy)

        # The request was successfully validated in load_ksr, now manipulate it
        ksr_bundles = ksr.bundles
        first_key = ksr_bundles[0].keys.pop()
        second_key = ksr_bundles[0].keys.pop()
        # Now switch the keys while keeping the key identifier. This should trigger
        # checks that verify that keys presented in multiple bundles stay invariant.
        new_first_key = replace(first_key, key_identifier=second_key.key_identifier)
        new_second_key = replace(second_key, key_identifier=first_key.key_identifier)
        ksr_bundles[0] = replace(ksr_bundles[0], keys = {new_first_key, new_second_key})
        ksr = replace(ksr, bundles=ksr_bundles)

        # Now try and verify the KSR again and ensure it fails signature validation
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation):
            validate_request(ksr, replace(policy, validate_signatures=False))

        # test that the check can be disabled
        validate_request(ksr, replace(policy, validate_signatures=False,
                                      keys_match_zsk_policy=False))


    def test_load_ksr_with_policy_violation(self):
        """ Test loading a KSR failing the supplied policy """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(warn_instead_of_fail=False,
                               num_bundles=99)
        with self.assertRaises(KSR_BUNDLE_COUNT_Violation):
            load_ksr(fn, policy, raise_original=True)

    def test_load_ksr_with_signatures_in_the_past(self):
        """ Test loading a KSR requesting signatures that has expired already """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(signature_horizon_days=180)
        with self.assertRaises(KSR_PolicyViolation):
            load_ksr(fn, policy, raise_original=True)

    def test_load_ksr_with_signatures_in_the_past2(self):
        """ Test loading a KSR requesting signatures that has expired already, but allowing it """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(signature_horizon_days=-1)
        load_ksr(fn, policy, raise_original=True)

    def test_load_ksr_with_signatures_in_the_past3(self):
        """ Test loading a KSR requesting signatures just outside of policy """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        # first load the KSR, allowing the old signatures
        policy = RequestPolicy(signature_horizon_days=-1)
        ksr = load_ksr(fn, policy, raise_original=True)
        first_expire = ksr.bundles[0].expiration
        dt_now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        # Now, try load the KSR again but say the last allowed expiration date is that
        # of the first bundles signature expiration date. This should fail all but the
        # first bundle.
        expire_days = (first_expire - dt_now).days
        policy = RequestPolicy(signature_horizon_days=expire_days)
        with self.assertRaises(KSR_PolicyViolation):
            load_ksr(fn, policy, raise_original=True)


class Test_Requests(unittest.TestCase):

    def _make_request(self, domain: str='.', request_policy: Optional[str] = None,
                     request_bundle: Optional[str] = None):
        if request_policy is None:
            request_policy = self._make_request_policy()
        if request_bundle is None:
            request_bundle = self._make_request_bundle()
        xml = f"""
    <KSR domain="{domain}" id="test" serial="0">
      <Request>
        {request_policy}

        {request_bundle}
      </Request>
    </KSR>
    """
        return xml.strip()

    def _make_request_policy(self, signature_algorithm: Optional[str]=None) -> str:
        if signature_algorithm is None:
            signature_algorithm = self._make_signature_algorithm()
        xml = f"""
        <RequestPolicy>
          <ZSK>
            <PublishSafety>P10D</PublishSafety>
            <RetireSafety>P10D</RetireSafety>
            <MaxSignatureValidity>P21D</MaxSignatureValidity>
            <MinSignatureValidity>P21D</MinSignatureValidity>
            <MaxValidityOverlap>P12D</MaxValidityOverlap>
            <MinValidityOverlap>P9D</MinValidityOverlap>
            {signature_algorithm}
          </ZSK>
        </RequestPolicy>
        """
        return xml.strip()

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="8">
              <RSA size="1024" exponent="65537"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _make_request_bundle(self,
                             bundle_inception: str = '2009-11-03T00:00:00',
                             bundle_expiration: str = '2009-11-17T23:59:59',
                             key_identifier: str = 'testkey',
                             key_tag: int = 49920,
                             algorithm: int = AlgorithmDNSSEC.RSASHA256.value,
                             pubkey: Optional[str] = None,
                             signature_inception: str = '2009-11-09T20:33:05',
                             signature_expiration: str = '2009-12-09T20:33:05',
                             signature: Optional[str] = None,
                             ) -> str:
        if pubkey is None:
            pubkey = 'AwEAAc2UsIt5d8lxdDil/4pLZVG8Y+kYc1Jf3RRAUzK1/ntFXcWL8gEDmuw6vBW8SiRF+HLKXTmEvqjE4SVV2HouhUb0SxR' \
                     'ts5/q59g++K9F1XsnDeMavXAA2R4Pca7VepNq7jisMEPpWc5U7FWeSdsFZtHus1oRQ4QdBLU1dZIaehsl'
        if signature is None:
            signature = 'ja4WnG5U5yPn2+1mUcfVNhUddqutmsqlhSQzMVtGbxP5RaoOqHWkU/I4fmFUC9Uov4WZ4KAi5Fy7KcexC57pBPsgQe4g' \
                        'i3ghyrcnQzLt4HPxNTLCPyQvbzHp+h2dXLvgLaGiMcWYzWn9aYE0RGQgMRSWd3NKmKsO/NnlKV41tSo='
        xml = f"""
        <RequestBundle id="test-id">
          <Inception>{bundle_inception}</Inception>
          <Expiration>{bundle_expiration}</Expiration>
          <Key keyIdentifier="{key_identifier}" keyTag="{key_tag}">
            <TTL>172800</TTL>
            <Flags>256</Flags>
            <Protocol>3</Protocol>
            <Algorithm>{algorithm}</Algorithm>
            <PublicKey>{pubkey}</PublicKey>
          </Key>
          <Signature keyIdentifier="{key_identifier}">
            <TTL>172800</TTL>
            <TypeCovered>DNSKEY</TypeCovered>
            <Algorithm>{algorithm}</Algorithm>
            <Labels>0</Labels>
            <OriginalTTL>172800</OriginalTTL>
            <SignatureInception>{signature_inception}</SignatureInception>
            <SignatureExpiration>{signature_expiration}</SignatureExpiration>
            <KeyTag>{key_tag}</KeyTag>
            <SignersName>.</SignersName>
            <SignatureData>{signature}</SignatureData>
          </Signature>
        </RequestBundle>
        """
        return xml.strip()


class Test_Valid_Requests(Test_Requests):

    def test_make_request(self):
        """ Test that the _make_request function produces a basically correct KSR """
        xml = self._make_request()
        policy = RequestPolicy(num_bundles=1,
                               check_cycle_length=False,
                               check_keys_match_ksk_operator_policy=False,
                               rsa_approved_key_sizes=[1024],
                               signature_validity_match_zsk_policy=False,
                               signature_check_expire_horizon=False,
                               approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
                               )
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, policy))

    def test_multiple_algorithms(self):
        """ Test validating a KSR with multiple ZSK algorithms """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="13">
              <ECDSA size="256"/>
            </SignatureAlgorithm>
            <SignatureAlgorithm algorithm="8">
              <RSA size="1024" exponent="65537"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy)
        policy = RequestPolicy(num_bundles=1,
                               check_cycle_length=False,
                               check_keys_match_ksk_operator_policy=False,
                               rsa_approved_key_sizes=[1024],
                               signature_validity_match_zsk_policy=False,
                               signature_check_expire_horizon=False,
                               approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name,
                                                    AlgorithmDNSSEC.ECDSAP256SHA256.name,
                                                    ],
                               enable_unsupported_ecdsa=True,
                               )
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, policy))


class Test_Invalid_Requests(Test_Requests):

    def test_bundle_with_unhandled_key_type(self):
        """ Test validating a KSR with a key/signature using an unhandled key type """

        bundle = self._make_request_bundle(algorithm=AlgorithmDNSSEC.ED448.value)
        xml = self._make_request(request_bundle=bundle)
        policy = RequestPolicy()
        request = request_from_xml(xml)
        with self.assertRaises(ValueError) as exc:
            validate_request(request, policy)
        self.assertIn('Key testkey in bundle test-id uses unhandled algorithm: AlgorithmDNSSEC.ED448',
                      str(exc.exception))

    def test_invalid_domain(self):
        """ Test validating a KSR for an unknown domain """
        xml = self._make_request(domain='test.', request_bundle='')
        policy = RequestPolicy(num_bundles=0,
                               approved_algorithms=['RSASHA256', 'DSA'],
                               num_keys_per_bundle=[],
                               num_different_keys_in_all_bundles=0,
                               )
        request = request_from_xml(xml)
        # DSA is not allowed, even if it is in approved_algorithms
        with self.assertRaises(KSR_DOMAIN_Violation) as exc:
            validate_request(request, policy)
        self.assertIn('not in policy\'s acceptable domains', str(exc.exception))

    def test_bundles_with_same_id(self):
        """ Test validating a KSR with two bundles having the same ID """
        bundle = self._make_request_bundle()
        xml = self._make_request(request_bundle=f'{bundle}\n       {bundle}\n')
        policy = RequestPolicy()
        request = request_from_xml(xml)
        with self.assertRaises(KSR_BUNDLE_UNIQUE_Violation) as exc:
            validate_request(request, policy)
        self.assertIn('More than one bundle with id test-id', str(exc.exception))

    def test_single_bundle_missing_info(self):
        """ Test validating a KSR with a single bundle missing mandatory data """
        bundle = """
        <RequestBundle id="test-non-unique-id">
          <Inception>2009-11-03T00:00:00</Inception>
          <Expiration>2009-11-17T23:59:59</Expiration>
        </RequestBundle>
        """.strip()
        xml = self._make_request(request_bundle=bundle)
        with self.assertRaises(ValueError) as exc:
            request_from_xml(xml)
        self.assertIn('Bundle test-non-unique-id missing mandatory Key', str(exc.exception))

    def test_DSA_algorithm_not_allowed(self):
        """ Test validating a KSR with the DSA algorithm """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="3">
              <DSA size="123"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle='')
        policy = RequestPolicy(num_bundles=0,
                               approved_algorithms=['RSASHA256', 'DSA'],
                               num_keys_per_bundle=[],
                               num_different_keys_in_all_bundles=0,
                               )
        request = request_from_xml(xml)
        # DSA is not allowed, even if it is in approved_algorithms
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(request, policy)
        self.assertIn('Algorithm DSA deprecated', str(exc.exception))


class Test_Validate_KSR_ECDSA(Test_Requests):

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="13">
              <ECDSA size="256"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _make_request_bundle(self,
                             bundle_inception: str = '2009-11-01T00:00:00',
                             bundle_expiration: str = '2009-11-22T00:00:00',
                             key_identifier: str = 'EC1',
                             key_tag: int = 45612,
                             algorithm: int = AlgorithmDNSSEC.ECDSAP256SHA256.value,
                             pubkey: Optional[str] = None,
                             signature_inception: str = '2009-11-09T20:33:05',
                             signature_expiration: str = '2009-12-09T20:33:05',
                             signature: Optional[str] = None,
                             ) -> str:
        if pubkey is None:
            # Key EC1 in SoftHSM
            pubkey = 'BGuqYyOGr0p/uKXm0MmP4Cuiml/a8FCPRDLerVyBS4jHmJlKTJmYk/nCbOp936DSh5SMu6+2WYJUI6K5AYfXbTE='
        if signature is None:
            # Signature generated manually using RRSIG data from the request below, and signed with SoftHSM
            signature = 'm3sDohyHv+OKUs3KUbCpNeLf5F4m0fy3v92T9XAOeZJ08fOnylYx+lpzkkAV5ZLVzR/rL2d4eIVbRizWumfHFQ=='
        return super()._make_request_bundle(bundle_inception=bundle_inception,
                                            bundle_expiration=bundle_expiration,
                                            key_identifier=key_identifier,
                                            key_tag=key_tag,
                                            algorithm=algorithm,
                                            pubkey=pubkey,
                                            signature_inception=signature_inception,
                                            signature_expiration=signature_expiration,
                                            signature=signature,
                                            )

    def test_validate_ksr_with_ecdsa_not_in_policy(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        policy = RequestPolicy(num_bundles=1,
                               approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
                               num_keys_per_bundle=[],
                               num_different_keys_in_all_bundles=0,
                               check_cycle_length=False,
                               check_keys_match_ksk_operator_policy=False,
                               enable_unsupported_ecdsa=True,
                               signature_check_expire_horizon=False,
                               )
        request = request_from_xml(xml)
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(request, policy)
        self.assertIn('ZSK policy is AlgorithmDNSSEC.ECDSAP256SHA256, but', str(exc.exception))

    def test_validate_ksr_with_ecdsa_key(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        policy = RequestPolicy(num_bundles=1,
                               approved_algorithms=[AlgorithmDNSSEC.ECDSAP256SHA256.name],
                               num_keys_per_bundle=[],
                               num_different_keys_in_all_bundles=0,
                               check_cycle_length=False,
                               check_keys_match_ksk_operator_policy=False,
                               enable_unsupported_ecdsa=True,
                               signature_check_expire_horizon=False,
                               )
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, policy))
