import base64
import datetime
import os
import unittest
from dataclasses import replace

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.ksr import load_ksr, request_from_xml
from kskm.ksr.validate import validate_request
from kskm.ksr.verify_bundles import KSR_BUNDLE_COUNT_Violation, KSR_BUNDLE_KEYS_Violation, KSR_BUNDLE_POP_Violation
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

    def test_load_ksr_with_policy_violation(self):
        """ Test loading a KSR failing the supplied policy """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(warn_instead_of_fail=False,
                               num_bundles=99)
        with self.assertRaises(KSR_BUNDLE_COUNT_Violation):
            load_ksr(fn, policy, raise_original=True)

    def test_DSA_algorithm_not_allowed(self):
        """ Test validating a KSR with the DSA algorithm """
        xml = """
<KSR domain="." id="test" serial="0">
  <Request>
    <RequestPolicy>
      <ZSK>
        <PublishSafety>P10D</PublishSafety>
        <RetireSafety>P10D</RetireSafety>
        <MaxSignatureValidity>P21D</MaxSignatureValidity>
        <MinSignatureValidity>P21D</MinSignatureValidity>
        <MaxValidityOverlap>P12D</MaxValidityOverlap>
        <MinValidityOverlap>P9D</MinValidityOverlap>
        <SignatureAlgorithm algorithm="3">
          <DSA size="123"/>
        </SignatureAlgorithm>
      </ZSK>
    </RequestPolicy>
  </Request>
</KSR>
"""
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
