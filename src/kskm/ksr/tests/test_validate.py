import os
import base64
import unittest
import pkg_resources

from dataclasses import replace

from kskm.ksr import load_ksr
from kskm.ksr.validate import validate_request
from kskm.ksr.policy import RequestPolicy
from kskm.ksr.verify_bundles import KSR_BUNDLE_POP_Violation


class Test_Validate_KSR(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')
        self.policy_fn = os.path.join(self.data_dir, 'response_policy.yaml')

    def test_validate_ksr_with_invalid_signature(self):
        """ Test manipulating SKR signature """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(warn_instead_of_fail=False,
                               # get around the issue of
                               # 'Signature validity 60 days > claimed max_signature_validity 21 days'
                               signature_validity_match_zsk_policy=False,
                               # get around the issue of
                               # 'Bundle X overlap 11 days, 0:00:00 with Y is < claimed minimum 12 days, 0:00:00'
                               check_bundle_overlap=False,
                               )
        ksr = load_ksr(fn, policy)

        # The response was successfully validated in load_ksr, now manipulate it
        first_bundle = ksr.bundles[0]
        sig = first_bundle.signatures.pop()
        # change the last byte of the signature
        sig_data = base64.b64decode(sig.signature_data)
        sig_data = sig_data[:-1] + b'\x00' if sig_data[-1] else b'\x01'
        # put everything back into the ksr
        sig = replace(sig, signature_data=base64.b64encode(sig_data))
        first_bundle.signatures.add(sig)
        ksr.bundles[0] = first_bundle

        # Now try and verify the SKR again and ensure it fails signature validation
        with self.assertRaises(KSR_BUNDLE_POP_Violation):
            validate_request(ksr, policy)

        # Test that the invalid SKR is accepted with signature validations turned off
        validate_request(ksr, replace(policy, validate_signatures=False))

    def test_load_ksr_with_policy_violation(self):
        """ Test loading an SKR failing the supplied policy """
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        policy = RequestPolicy(warn_instead_of_fail=False,
                               num_bundles = 99)
        with self.assertRaises(RuntimeError):
            load_ksr(fn, policy)

