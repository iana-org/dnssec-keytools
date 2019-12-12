import base64
import binascii
import datetime
import io
import os
import unittest
from dataclasses import replace
from typing import Optional

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY
from kskm.common.parse_utils import duration_to_timedelta
from kskm.ksr import load_ksr, request_from_xml
from kskm.ksr.validate import validate_request
from kskm.ksr.verify_bundles import KSR_BUNDLE_COUNT_Violation, KSR_BUNDLE_KEYS_Violation, KSR_BUNDLE_POP_Violation, \
    KSR_BUNDLE_UNIQUE_Violation, KSR_BUNDLE_CYCLE_DURATION_Violation
from kskm.ksr.verify_header import KSR_DOMAIN_Violation
from kskm.ksr.verify_policy import KSR_POLICY_ALG_Violation, KSR_PolicyViolation
from kskm.misc.hsm import get_p11_key, sign_using_p11


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

    def setUp(self) -> None:
        # a policy that works with the default _make_request
        self.policy = RequestPolicy(num_bundles=1,
                                    check_cycle_length=False,
                                    check_keys_match_ksk_operator_policy=False,
                                    rsa_approved_key_sizes=[1024],
                                    signature_validity_match_zsk_policy=False,
                                    signature_check_expire_horizon=False,
                                    approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
                                    )

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

    def _make_request_bundle(self, bundle_id: str = 'test-id',
                             bundle_inception: str = '2009-11-03T00:00:00',
                             bundle_expiration: str = '2009-11-17T23:59:59',
                             key_identifier: str = 'testkey',
                             key_tag: int = 49920,
                             flags: int = FlagsDNSKEY.ZONE.value,
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
        <RequestBundle id="{bundle_id}">
          <Inception>{bundle_inception}</Inception>
          <Expiration>{bundle_expiration}</Expiration>
          <Key keyIdentifier="{key_identifier}" keyTag="{key_tag}">
            <TTL>172800</TTL>
            <Flags>{flags}</Flags>
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
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, self.policy))

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
        policy = replace(self.policy,
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
        self.assertEqual('Key testkey in bundle test-id uses unhandled algorithm: AlgorithmDNSSEC.ED448',
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
        self.assertEqual('More than one bundle with id test-id', str(exc.exception))

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
        self.assertEqual('Bundle test-non-unique-id missing mandatory Key', str(exc.exception))

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
        self.assertEqual('Algorithm DSA deprecated', str(exc.exception))

    def test_wrong_RSA_key_size(self):
        """ Test a request with an RSA key of a size not matching the ZSK policy """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="8">
              <RSA size="2048" exponent="65537"/>
            </SignatureAlgorithm>
        """.strip()
        request_policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=request_policy)
        request = request_from_xml(xml)
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation) as exc:
            self.assertTrue(validate_request(request, self.policy))
        self.assertEqual('Key testkey in bundle test-id does not match the ZSK SignaturePolicy', str(exc.exception))

    def test_wrong_RSA_key_exponent(self):
        """ Test a request with an RSA key with an exponent not matching the ZSK policy """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="8">
              <RSA size="1024" exponent="3"/>
            </SignatureAlgorithm>
        """.strip()
        request_policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=request_policy)
        request = request_from_xml(xml)
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation) as exc:
            self.assertTrue(validate_request(request, self.policy))
        self.assertEqual('Key testkey in bundle test-id does not match the ZSK SignaturePolicy', str(exc.exception))

        # test that we don't get an exception if we turn off the exponent validation (possible because some old
        # requests in the KSR archive have the wrong exponent)
        policy = replace(self.policy, rsa_exponent_match_zsk_policy=False)
        self.assertTrue(validate_request(request, policy))

    def test_bad_key_flags(self):
        """ Test a request with a non-ZSK key  """
        bundle = self._make_request_bundle(flags=FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value)
        xml = self._make_request(request_bundle=bundle)
        request = request_from_xml(xml)
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation) as exc:
            self.assertTrue(validate_request(request, self.policy))
        self.assertEqual('Key testkey in bundle test-id has flags 257, only 256 acceptable', str(exc.exception))

    def test_wrong_key_tag(self):
        """ Test a request with a key with the wrong tag """
        bundle = self._make_request_bundle(key_tag=12345)
        xml = self._make_request(request_bundle=bundle)
        request = request_from_xml(xml)
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation) as exc:
            self.assertTrue(validate_request(request, self.policy))
        self.assertEqual('Key testkey in bundle test-id has key tag 12345, should be 49920', str(exc.exception))

    def test_extra_key_in_bundle(self):
        """ Test a request with a key without a matching signature (no proof of possession) """
        RSA1 = """
        AwEAAcBH41eazGJG/DBdDmKxGxO8Bv4XbgNQiButvR60Aqzprd6DMT2J0xtR91MkkGYKj9Gc0nO9nBQFC4/zPEAlqE1HWnx4E57o
        BHSpij/B5MJYHIW1khGrjuRYooy8/q8C3U/PktxTxc6UlUqmPGL/dk5WYUOQsP8zayx/QSgc7wCR17CUvoaVyM05SPQyW20ztKEu
        oLkbWRG0vIDH84txq9oCBg4feuWVNl7VIIh3Sd7wRksMn2G8yz7zCs9btOP7SOcNlsGyw5f4syQmgQU5/UCt0FVF6w2LgT9pqR9r
        /+3kiO25oUc8+wZnA+ZhYVESoKCMb6G7UHty+6CTvQOxh8M=
        """
        RSA2 = """
        AwEAAbVjMqPCjRUQ2rueoToPt06YG22QLDU/Ax2xljviy4tyf2atR2GdDEEia/TwhGbtOIvID6D9xk6TOxA7Ka8RnYWUy5tdO8
        d2yr1V1v2u6dH6PgEAibAgXLhnG7dX62zyYhCgCIcREFVI+t3jdZp79mxp/Ath62R8xgAgOhsNY370WkfQvNE4sD+x15vWGL9yUJ
        fWPn0Nw6TD8IxRnggo4uZLWZRkQ6RDPJTDYY3Amm3rhPuNU+PTfp41lO2lfX7si/KXIP3az9gFkzpAepzWiRe+PhgLkjYcNQslU6
        QRRa+5Fs2821tH4gIQdpwNA2DxaXmAFvozVEYIaHBEISEuaGU=
        """
        signature = """
        cKdTcK5eJKGNj5oCPOXnsny8hCmzxoY5/XS0o1MbebiJ+5cmdrTPyrLZoMv59NOSffVq8HmZGkSul6v/6Ng0GrHfGr2Fa/tFFkbS
        6NRguaC+OgFnJb0/RToq8UgHnb7YMo156PpkK2dYqJUXtjF+xm/EzKsZ8eijMAiVMhlRW7vTJ6/1CY/J+GWGqpCYU5zGhCAPyMUS
        uFQsE6sTV5FLhx9jyYLTUPYH8TfzgQnJ7H7eNRVyPrCde7+cn3jh3QdDDScuMDvlgN4Fqw2Y8QRdymgREsQRZTk2xymRLhAmE/mP
        eBwfEcsyA+83mdAZN/6svoqQ/rbWXNPgRDuNNc4y6g==
        """
        extra_key = f"""
              <Key keyIdentifier="RSA2" keyTag="33945">
                <TTL>172800</TTL>
                <Flags>256</Flags>
                <Protocol>3</Protocol>
                <Algorithm>8</Algorithm>
                <PublicKey>{RSA2}</PublicKey>
              </Key>
        """
        bundle = f"""
            <RequestBundle id="test-id">
              <Inception>2010-11-03T00:00:00</Inception>
              <Expiration>2010-11-17T23:59:59</Expiration>
              <Key keyIdentifier="RSA1" keyTag="25485">
                <TTL>172800</TTL>
                <Flags>256</Flags>
                <Protocol>3</Protocol>
                <Algorithm>8</Algorithm>
                <PublicKey>{RSA1}</PublicKey>
              </Key>
              {extra_key}
              <Signature keyIdentifier="RSA1">
                <TTL>172800</TTL>
                <TypeCovered>DNSKEY</TypeCovered>
                <Algorithm>8</Algorithm>
                <Labels>0</Labels>
                <OriginalTTL>172800</OriginalTTL>
                <SignatureInception>2010-11-09T20:33:05</SignatureInception>
                <SignatureExpiration>2010-12-09T20:33:05</SignatureExpiration>
                <KeyTag>25485</KeyTag>
                <SignersName>.</SignersName>
                <SignatureData>{signature}</SignatureData>
              </Signature>
            </RequestBundle>
        """.strip()
        signature_algorithm = """
            <SignatureAlgorithm algorithm="8">
              <RSA size="2048" exponent="65537"/>
            </SignatureAlgorithm>
        """.strip()
        request_policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=request_policy, request_bundle=bundle)
        request = request_from_xml(xml)
        policy = replace(self.policy, rsa_approved_key_sizes=[1024, 2048])
        with self.assertRaises(KSR_BUNDLE_POP_Violation) as exc:
            validate_request(request, policy)

        self.assertRegex(str(exc.exception),
                         'Key Key.+key_identifier=\'RSA2\'.+ was not used to sign the keys in bundle test-id')


class Test_Validate_KSR_ECDSA(Test_Requests):

    def setUp(self):
        super().setUp()
        self.policy = replace(self.policy,
                              enable_unsupported_ecdsa=True,
                              approved_algorithms=[AlgorithmDNSSEC.ECDSAP256SHA256.name],
                              )

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.ECDSAP256SHA256.value}">
              <ECDSA size="256"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _make_request_bundle(self,
                             bundle_id: str = 'test-id',
                             bundle_inception: str = '2009-11-01T00:00:00',
                             bundle_expiration: str = '2009-11-22T00:00:00',
                             key_identifier: str = 'EC1',
                             key_tag: int = 45612,
                             flags: int = FlagsDNSKEY.ZONE.value,
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
        return super()._make_request_bundle(bundle_id=bundle_id,
                                            bundle_inception=bundle_inception,
                                            bundle_expiration=bundle_expiration,
                                            key_identifier=key_identifier,
                                            key_tag=key_tag,
                                            flags=flags,
                                            algorithm=algorithm,
                                            pubkey=pubkey,
                                            signature_inception=signature_inception,
                                            signature_expiration=signature_expiration,
                                            signature=signature,
                                            )

    def test_validate_ksr_with_ecdsa_not_in_policy(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name])
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(request, policy)
        self.assertIn('ZSK policy is AlgorithmDNSSEC.ECDSAP256SHA256, but', str(exc.exception))

    def test_validate_ksr_with_ecdsa_key(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, self.policy))

    def test_wrong_size_EC_key(self):
        """ Test a request with an RSA key of a size not matching the ZSK policy """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="13">
              <ECDSA size="384"/>
            </SignatureAlgorithm>
        """.strip()
        request_policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=request_policy)
        request = request_from_xml(xml)
        policy = replace(self.policy, approved_algorithms=[AlgorithmDNSSEC.ECDSAP384SHA384.name])
        with self.assertRaises(KSR_BUNDLE_KEYS_Violation) as exc:
            self.assertTrue(validate_request(request, policy))
        self.assertIn('Key EC1 in bundle test-id does not match the ZSK SignaturePolicy', str(exc.exception))


class Test_Requests_With_Two_Bundles(Test_Requests):

    def setUp(self):
        super().setUp()
        # a policy that works with the default _make_request
        self.policy = RequestPolicy(num_bundles=2,
                                    num_keys_per_bundle=[1, 1],
                                    num_different_keys_in_all_bundles=1,
                                    rsa_approved_key_sizes=[2048],
                                    approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
                                    validate_signatures=False,  # signatures are tested elsewhere
                                    signature_horizon_days=-1,  # allow signatures in the past
                                    min_cycle_inception_length=duration_to_timedelta('P11D'),
                                    )

    def _make_request(self, domain: str='.', request_policy: Optional[str] = None,
                      bundle1: Optional[str] = None, bundle2: Optional[str] = None):
        # the public part of key RSA1 in softhsm
        RSA1 = """
        AwEAAcBH41eazGJG/DBdDmKxGxO8Bv4XbgNQiButvR60Aqzprd6DMT2J0xtR91MkkGYKj9Gc0nO9nBQFC4/zPEAlqE1HWnx4E57o
        BHSpij/B5MJYHIW1khGrjuRYooy8/q8C3U/PktxTxc6UlUqmPGL/dk5WYUOQsP8zayx/QSgc7wCR17CUvoaVyM05SPQyW20ztKEu
        oLkbWRG0vIDH84txq9oCBg4feuWVNl7VIIh3Sd7wRksMn2G8yz7zCs9btOP7SOcNlsGyw5f4syQmgQU5/UCt0FVF6w2LgT9pqR9r
        /+3kiO25oUc8+wZnA+ZhYVESoKCMb6G7UHty+6CTvQOxh8M=
        """
        signature = """
        qeD7321YJ0g2ihT8XHPGIkMVumQoL7tdTQ6fMttyxmLeCMSE3K2cQBBQd622FGuF88JRiZKrQxWMfx2aow5k0WehytAhqaXy
        7DVzNJ+vxa0N5JoczkTMdNp6zF/L5DF2xbxgY88Yu9WVXZ0vpn5rx8bHwgsvrTfGhYWHipMgHBZpgmpWR2sS60mW/FnljmQE
        oiTk8np6QRGEVXZXX1QA7D/x+ey25aQfJxMuBT9ajTnUiGhUQz4GN6Eg5lgN6Ys3Yrqh7UuaDZjGTmrpNbbuym9VY0zTh7fj
        4avLezCphA7ZR2L8V1zkTdekC9qa+AGNFpK6BwnWLnI0ZWF9JqUs/Q==
        """.strip()
        if request_policy is None:
            request_policy = self._make_request_policy()
        if bundle1 is None:
            bundle1 = self._make_request_bundle(bundle_id='test-1',
                                                bundle_inception='2019-01-01T00:00:00',
                                                bundle_expiration='2019-01-22T00:00:00',
                                                key_identifier='RSA1',
                                                key_tag=25485,
                                                pubkey=RSA1,
                                                signature_inception='2019-01-01T00:00:00',
                                                signature_expiration='2019-01-22T00:00:00',
                                                signature=signature,
                                                )
        if bundle2 is None:
            bundle2 = self._make_request_bundle(bundle_id='test-2',
                                                bundle_inception='2019-01-12T00:00:00',
                                                bundle_expiration='2019-02-02T00:00:00',
                                                key_identifier='RSA1',
                                                key_tag=25485,
                                                pubkey=RSA1,
                                                signature_inception='2019-01-12T00:00:00',
                                                signature_expiration='2019-02-02T00:00:00',
                                                signature=signature,
                                                )
        xml = f"""
    <KSR domain="{domain}" id="test" serial="0">
      <Request>
        {request_policy}

        {bundle1}

        {bundle2}
      </Request>
    </KSR>
    """
        return xml.strip()

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.RSASHA256.value}">
              <RSA size="2048" exponent="65537"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def test_request_with_two_bundles(self):
        """ Test that the _make_request function produces a basically correct KSR """
        xml = self._make_request()
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, self.policy))

    def test_min_bundle_interval(self):
        """ Test two bundles with too low interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, min_bundle_interval=duration_to_timedelta('P15D'))
        with self.assertRaises(KSR_BUNDLE_CYCLE_DURATION_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual('Bundle #1 (test-2) interval 11 days < minimum 15 days', str(exc.exception))

    def test_max_bundle_interval(self):
        """ Test two bundles with too large interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, max_bundle_interval=duration_to_timedelta('P9D'))
        with self.assertRaises(KSR_BUNDLE_CYCLE_DURATION_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual('Bundle #1 (test-2) interval 11 days > maximum 9 days', str(exc.exception))

    def test_min_bundle_cycle_inception(self):
        """ Test two bundles with too small inception interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, min_cycle_inception_length=duration_to_timedelta('P20D'))
        with self.assertRaises(KSR_BUNDLE_CYCLE_DURATION_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual('Cycle inception length (11 days) less than minimum acceptable length 20 days',
                         str(exc.exception))

    def test_max_bundle_cycle_inception(self):
        """ Test two bundles with too large inception interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, max_cycle_inception_length=duration_to_timedelta('P10D'))
        with self.assertRaises(KSR_BUNDLE_CYCLE_DURATION_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual('Cycle length (11 days) greater than maximum acceptable length 11 days',
                         str(exc.exception))




def _sign_using_softhsm(data: bytes, softhsm_signing_key='RSA1') -> None:
    # This is how to calculate the correct ZSK operator signature using the key in SoftHSM
    from kskm.common.config import KSKMConfig
    from kskm.misc.hsm import init_pkcs11_modules_from_dict
    import hashlib
    softhsm_dir = pkg_resources.resource_filename(__name__, '../../../../testing/softhsm')
    _cfg_fn = os.path.join(softhsm_dir, 'ksrsigner.yaml')

    with open(_cfg_fn, 'r') as fd:
        conf = io.StringIO(fd.read())
    config = KSKMConfig.from_yaml(conf)
    p11modules = init_pkcs11_modules_from_dict(config.hsm)

    signing_key = get_p11_key(softhsm_signing_key, p11modules, public=False)
    rrsig = binascii.unhexlify(data)
    signature_data = sign_using_p11(signing_key, rrsig, AlgorithmDNSSEC.RSASHA256)
    correct_sig = base64.b64encode(signature_data)

    print(f'Correct signature (using key {softhsm_signing_key}) for RRSIG {binascii.hexlify(rrsig)}\n'
          f' (SHA-256 digest {hashlib.sha256(rrsig).hexdigest()}):\n{correct_sig}')
