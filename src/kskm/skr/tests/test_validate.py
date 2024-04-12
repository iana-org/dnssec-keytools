import base64
import os
import unittest
from dataclasses import replace

import pkg_resources
from kskm.common.config_misc import ResponsePolicy
from kskm.skr import load_skr
from kskm.skr.validate import InvalidSignatureViolation, validate_response


class Test_Validate_SKR(unittest.TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = pkg_resources.resource_filename(__name__, "data")
        self.policy_fn = os.path.join(self.data_dir, "response_policy.yaml")

    def test_validate_skr_with_invalid_signature(self) -> None:
        """Test manipulating SKR signature"""
        fn = os.path.join(self.data_dir, "skr-root-2018-q1-0-d_to_e.xml")
        policy = ResponsePolicy()
        skr = load_skr(fn, policy)

        # The response was successfully validated in load_skr, now manipulate it
        first_bundle = skr.bundles[0]
        sig = first_bundle.signatures.pop()
        # change the last byte of the signature
        sig_data = base64.b64decode(sig.signature_data)
        sig_data = sig_data[:-1] + b"\x00" if sig_data[-1] else b"\x01"
        # put everything back into the skr
        sig = replace(sig, signature_data=base64.b64encode(sig_data))
        first_bundle.signatures.add(sig)
        skr.bundles[0] = first_bundle

        # Now try and verify the SKR again and ensure it fails signature validation
        with self.assertRaises(InvalidSignatureViolation):
            validate_response(skr, policy)

        # Test that the invalid SKR is accepted with signature validations turned off
        validate_response(skr, replace(policy, validate_signatures=False))

    def test_load_skr_with_policy_violation(self) -> None:
        """Test loading an SKR failing the supplied policy"""
        fn = os.path.join(self.data_dir, "skr-root-2018-q1-0-d_to_e.xml")
        policy = ResponsePolicy(num_bundles=99)
        with self.assertRaises(RuntimeError):
            load_skr(fn, policy)
