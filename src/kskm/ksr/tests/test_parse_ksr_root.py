import os
import unittest
from dataclasses import replace

import pkg_resources

import kskm.ksr.verify_bundles
import kskm.ksr.verify_policy
from kskm.common.config_misc import RequestPolicy
from kskm.ksr import load_ksr, request_from_xml


class TestParseRealKSRs(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')

    def test_parse_ksr_root_2009_q4_2(self):
        """ Test parsing ksr-root-2009-q4-2.xml """
        fn = os.path.join(self.data_dir, 'ksr-root-2009-q4-2.xml')
        with open(fn, 'r') as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        self.assertEqual('acaf327e-65ff-448a-8a7c-519698b659ff', ksr.id)
        self.assertEqual('.', ksr.domain)
        # There are other test cases covering parts of the parsing in detail, so
        # here we only do cursory checks of the high level. Comparing 'ksr' with
        # a complete 'Request' instance would make it too rigid, at least at this
        # point in development.
        self.assertEqual(10 * 86400, ksr.zsk_policy.publish_safety.total_seconds())
        bundle_ids = sorted([this.id for this in ksr.bundles])
        expected_ids = sorted(['694627a9-7178-423d-93f5-6e2861326816',
                               '74d20c98-53a7-4f5f-a8d7-7a7c42fa0f70',
                               '7d8138c5-8fae-4bdb-8d4f-a6152725baf0',
                               'bc3438f4-8440-476c-bfca-8e6ea5edbe8b',
                               'd8db73a7-238b-4d5c-a817-412412f1d11a',
                               'e9855a7e-6951-4e73-a9c6-83148bfbd170',
                               ])
        self.assertEqual(expected_ids, bundle_ids)

    def test_parse_ksr_root_2010_q1_0(self):
        """ Test parsing ksr-root-2010-q1-0.xml """
        fn = os.path.join(self.data_dir, 'ksr-root-2010-q1-0.xml')
        with open(fn, 'r') as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        self.assertEqual('ba050f09-e208-4a32-bad2-91de3f2c2a12', ksr.id)
        self.assertEqual('.', ksr.domain)
        # There are other test cases covering parts of the parsing in detail, so
        # here we only do cursory checks of the high level. Comparing 'ksr' with
        # a complete 'Request' instance would make it too rigid, at least at this
        # point in development.
        self.assertEqual(10 * 86400, ksr.zsk_policy.publish_safety.total_seconds())
        bundle_ids = sorted([this.id for this in ksr.bundles])
        expected_ids = sorted(['086ce566-8cb9-4d8d-a99e-169789686ba7',
                               '203f40d9-13f9-499e-8773-d5be8c62b288',
                               '2e1f264e-4d94-4d6e-ae1a-73726a5e727e',
                               '2eb82027-fd70-49ca-8a91-831753df4bac',
                               '3ea2e9bd-0bcb-4bd4-b7aa-2e9bb1c809a0',
                               '4d875ce3-3f67-4002-87e8-1955442be60b',
                               '6433bb72-5a53-4297-993a-11ecc42080ef',
                               'c128ebfe-bd07-498e-bd6b-f50f91e14d29',
                               'c477e58c-d4e1-433e-bf7a-6381aaa3b7b4',
                               ])
        self.assertEqual(expected_ids, bundle_ids)

    def test_parse_ksr_root_2010_q2_0(self):
        """ Test parsing ksr-root-2010-q2-0.xml """
        fn = os.path.join(self.data_dir, 'ksr-root-2010-q2-0.xml')
        policy = RequestPolicy(rsa_exponent_match_zsk_policy=False,
                               rsa_approved_key_sizes=[1024],
                               check_bundle_overlap=False,
                               signature_validity_match_zsk_policy=False,
                               signature_horizon_days=0,
                               )
        ksr = load_ksr(fn, policy, raise_original=True)
        self.assertEqual('14d45450-618c-4414-8e1e-9078ffb0ed51', ksr.id)
        self.assertEqual('.', ksr.domain)
        # There are other test cases covering parts of the parsing in detail, so
        # here we only do cursory checks of the high level. Comparing 'ksr' with
        # a complete 'Request' instance would make it too rigid, at least at this
        # point in development.
        self.assertEqual(10 * 86400, ksr.zsk_policy.publish_safety.total_seconds())
        bundle_ids = sorted([this.id for this in ksr.bundles])
        expected_ids = sorted(['25874fbf-e16c-45da-90d5-40e6e07b7d00',
                               '3a1df84e-c800-4826-80e9-dcf0dd92a368',
                               '3f232020-5bd0-410f-866d-eeecd04af522',
                               '833555b4-822a-40c6-bbeb-1d55b79f1321',
                               'a73702a2-e6cc-4934-80bb-9605046df56a',
                               'adaec7d5-22e4-49f3-b3b0-29fca3e1c65d',
                               'b47dfa22-8b20-4a07-9b29-b737ccc2bb6b',
                               'd94d34ee-f78a-49cd-a2b1-97c9b02b9ca9',
                               'f1563671-bec2-4a7c-8071-f4215a02af35',
                               ])
        self.assertEqual(expected_ids, bundle_ids)

    def test_parse_ksr_root_2010_q2_0_verify_fails(self):
        """ Test parsing ksr-root-2010-q2-0.xml """
        fn = os.path.join(self.data_dir, 'ksr-root-2010-q2-0.xml')
        # This policy actually works for this file
        policy = RequestPolicy(rsa_exponent_match_zsk_policy=False,
                               rsa_approved_key_sizes=[1024],
                               check_bundle_overlap=False,
                               signature_validity_match_zsk_policy=False,
                               )

        # Now test one error at a time and ensure the right exceptions are raised

        with self.assertRaises(kskm.ksr.verify_bundles.KSR_BUNDLE_KEYS_Violation):
            load_ksr(fn, replace(policy, rsa_exponent_match_zsk_policy=True), raise_original=True)

        with self.assertRaises(kskm.ksr.verify_policy.KSR_POLICY_PARAMS_Violation):
            load_ksr(fn, replace(policy, rsa_approved_key_sizes=[2048]), raise_original=True)

        with self.assertRaises(kskm.ksr.verify_policy.KSR_POLICY_SIG_OVERLAP_Violation):
            load_ksr(fn, replace(policy, check_bundle_overlap=True), raise_original=True)

        with self.assertRaises(kskm.ksr.verify_policy.KSR_POLICY_SIG_VALIDITY_Violation):
            load_ksr(fn, replace(policy, signature_validity_match_zsk_policy=True), raise_original=True)

    def test_load_ksr_2016(self):
        """ Test complete load and validate 2016 """
        # Exception: Failed validating KSR request in file ksr-root-2016-q3-0.xml:
        #            Key 3028312630240603550403131d566572695369676e20444e5353656320526f6f74205a534b20312d3237
        #            in bundle df64b6da-c1c7-49df-9958-bef478c095d4 is RSA-1024, but ZSK SignaturePolicy says 2048
        _rsa_approved_key_sizes = [1024, 2048]
        # Exception: Failed validating KSR request in file ksr-root-2016-q3-0.xml:
        #            Bundle "id=836cf0d6 2016-07-11->2016-07-25" overlap 4 days, 23:59:59 with
        #                   "id=df64b6da 2016-07-01->2016-07-15" is < claimed minimum 5 days
        _check_bundle_overlap = False
        # Exception: Failed validating KSR request in file ksr-root-2016-q3-0.xml:
        #            Bundle validity 14 days, 23:59:59 < claimed min_signature_validity 15 days
        #            (in bundle df64b6da-c1c7-49df-9958-bef478c095d4)
        _signature_validity_match_zsk_policy = False
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle signature expire in the past
        _signature_horizon = 0
        policy = RequestPolicy(rsa_approved_key_sizes=_rsa_approved_key_sizes,
                               check_bundle_overlap=_check_bundle_overlap,
                               signature_validity_match_zsk_policy=_signature_validity_match_zsk_policy,
                               signature_horizon_days=_signature_horizon,
                               )
        fn = os.path.join(self.data_dir, 'ksr-root-2016-q3-0.xml')
        ksr = load_ksr(fn, policy)
        self.assertEqual('2dc3b3f3-2db2-4074-a5c9-535dcfc04f63', ksr.id)

    def test_load_ksr_2018(self):
        """ Test complete load and validate 2018 """
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle signature expire in the past
        _signature_horizon = 0
        policy = RequestPolicy(signature_horizon_days=_signature_horizon,
                               )
        fn = os.path.join(self.data_dir, 'ksr-root-2018-q1-0-d_to_e.xml')
        ksr = load_ksr(fn, policy)
        self.assertEqual('4fe9bb10-6f6b-4503-8575-7824e2d66925', ksr.id)
