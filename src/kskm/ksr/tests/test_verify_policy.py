import datetime
import os
import unittest
from dataclasses import replace

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmDNSSEC
from kskm.common.parse_utils import duration_to_timedelta
from kskm.ksr import load_ksr, request_from_xml
from kskm.ksr.tests.common import (
    Test_Requests,
    Test_Requests_With_Two_Bundles,
    Test_Validate_KSR_ECDSA,
)
from kskm.ksr.validate import validate_request
from kskm.ksr.verify_policy import (
    KSR_POLICY_ALG_Violation,
    KSR_POLICY_BUNDLE_INTERVAL_Violation,
    KSR_POLICY_KEYS_Violation,
    KSR_POLICY_SIG_OVERLAP_Violation,
    KSR_POLICY_SIG_VALIDITY_Violation,
    KSR_PolicyViolation,
)


class Test_Validate_KSR_policy(unittest.TestCase):
    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, "data")
        self.policy_fn = os.path.join(self.data_dir, "response_policy.yaml")

    def test_load_ksr_with_signatures_in_the_past(self):
        """ Test loading a KSR requesting signatures that has expired already """
        fn = os.path.join(self.data_dir, "ksr-root-2018-q1-0-d_to_e.xml")
        policy = RequestPolicy(signature_horizon_days=180)
        with self.assertRaises(KSR_PolicyViolation):
            load_ksr(fn, policy, raise_original=True)

    def test_load_ksr_with_signatures_in_the_past2(self):
        """ Test loading a KSR requesting signatures that has expired already, but allowing it """
        fn = os.path.join(self.data_dir, "ksr-root-2018-q1-0-d_to_e.xml")
        policy = RequestPolicy(signature_horizon_days=-1)
        load_ksr(fn, policy, raise_original=True)

    def test_load_ksr_with_signatures_in_the_past3(self):
        """ Test loading a KSR requesting signatures just outside of policy """
        fn = os.path.join(self.data_dir, "ksr-root-2018-q1-0-d_to_e.xml")
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


class Test_Invalid_Requests_policy(Test_Requests):
    def setUp(self):
        super().setUp()
        self.policy = RequestPolicy(
            num_bundles=0, num_keys_per_bundle=[], num_different_keys_in_all_bundles=0,
        )

    def test_DSA_algorithm_not_allowed(self):
        """ Test validating a KSR with the DSA algorithm """
        signature_algorithm = """
            <SignatureAlgorithm algorithm="3">
              <DSA size="123"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle="")
        request = request_from_xml(xml)
        # DSA is not allowed, even if it is in approved_algorithms
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(
                request, replace(self.policy, approved_algorithms=["RSASHA256", "DSA"])
            ),
        self.assertEqual("Algorithm DSA deprecated", str(exc.exception))

    def test_RSASHA1_not_supported(self):
        """ Test validating a KSR with RSA-SHA1 (not supported) """
        signature_algorithm = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.RSASHA1.value}">
              <RSA size="1024" exponent="3"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle="")
        request = request_from_xml(xml)
        # RSA is supported, but not RSASHA1
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(
                request, replace(self.policy, approved_algorithms=["RSASHA256"])
            ),
        self.assertEqual("Algorithm RSASHA1 not supported", str(exc.exception))

    def test_RSA_wrong_size(self):
        """ Test validating a KSR with RSA-1024, with policy stipulating RSA-2048 """
        signature_algorithm = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.RSASHA256.value}">
              <RSA size="1024" exponent="65537"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle="")
        request = request_from_xml(xml)
        # RSA is supported, but not RSASHA1
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(
                request, replace(self.policy, approved_algorithms=["RSASHA256"])
            ),
        self.assertEqual(
            "ZSK policy has RSA-1024, but policy dictates [2048]", str(exc.exception)
        )

    def test_RSA_wrong_exponent(self):
        """ Test validating a KSR with RSA-SHA1 (not supported) """
        signature_algorithm = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.RSASHA256.value}">
              <RSA size="2048" exponent="17"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle="")
        request = request_from_xml(xml)
        # RSA is supported, but not RSASHA1
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(
                request, replace(self.policy, approved_algorithms=["RSASHA256"])
            ),
        self.assertEqual(
            "ZSK policy has RSA exponent 17, but policy dictates [3, 65537]",
            str(exc.exception),
        )

    def test_ECDSA_not_enabled(self):
        """ Test validating a KSR with ECDSA (not enabled) """
        signature_algorithm = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.ECDSAP384SHA384.value}">
              <ECDSA size="384"/>
            </SignatureAlgorithm>
        """.strip()
        policy = self._make_request_policy(signature_algorithm=signature_algorithm)
        xml = self._make_request(request_policy=policy, request_bundle="")
        request = request_from_xml(xml)
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(
                request, replace(self.policy, approved_algorithms=["RSASHA256"])
            ),
        self.assertEqual("Algorithm ECDSA is not supported", str(exc.exception))


class Test_ECDSA_Policy(Test_Validate_KSR_ECDSA):
    def test_validate_ksr_with_ecdsa_not_in_policy(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(
            self.policy, approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name]
        )
        with self.assertRaises(KSR_POLICY_ALG_Violation) as exc:
            validate_request(request, policy)
        self.assertIn(
            "ZSK policy has AlgorithmDNSSEC.ECDSAP256SHA256, but", str(exc.exception)
        )

        # test disabling check
        policy = replace(policy, signature_algorithms_match_zsk_policy=False)
        self.assertTrue(validate_request(request, policy))

    def test_validate_ksr_with_ecdsa_key(self):
        """ Test KSR with ECDSA key """
        xml = self._make_request()
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, self.policy))


class Test_KSK_Policy_Two_Bundles(Test_Requests_With_Two_Bundles):
    def test_request_with_two_bundles(self):
        """ Test that the _make_request function produces a basically correct KSR """
        xml = self._make_request()
        request = request_from_xml(xml)
        self.assertTrue(validate_request(request, self.policy))

    def test_zsk_policy_no_bundle_overlap(self):
        """ Test two bundles not overlapping (against ZSK policy) """
        signature_algorithm = self._make_signature_algorithm()
        request_policy = f"""
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

        bundle1, bundle2, = self._get_two_bundles()
        xml = self._make_request(
            request_policy=request_policy, bundle1=bundle1, bundle2=bundle2
        )
        request = request_from_xml(xml)
        policy = replace(
            self.policy,
            check_bundle_intervals=False,  # want to test against ZSK policy, not KSK policy
            check_cycle_length=False,  # want to test against ZSK policy, not KSK policy
        )
        with self.assertRaises(KSR_POLICY_SIG_OVERLAP_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            'Bundle "test-2" does not overlap with previous bundle "test-1" (2019-02-01 00:00:00+00:00 > '
            "2019-01-22 00:00:00+00:00)",
            str(exc.exception),
        )

    def test_zsk_policy_min_bundle_overlap(self):
        """ Test two bundles with too little overlap (against ZSK policy) """
        bundle1, bundle2, = self._get_two_bundles(
            bundle1_inception="2019-01-01T00:00:00",
            bundle1_expiration="2019-01-22T00:00:00",
            bundle2_inception="2019-01-20T00:00:00",
            bundle2_expiration="2019-02-12T00:00:00",
        )
        xml = self._make_request(bundle1=bundle1, bundle2=bundle2)
        request = request_from_xml(xml)
        policy = replace(
            self.policy,
            check_bundle_intervals=False,  # want to test against ZSK policy, not KSK policy
            check_cycle_length=False,  # want to test against ZSK policy, not KSK policy
        )
        with self.assertRaises(KSR_POLICY_SIG_OVERLAP_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            'Bundle "id=test-2 2019-01-20->2019-02-12" overlap 2 days with '
            '"id=test-1 2019-01-01->2019-01-22" is < claimed minimum 9 days',
            str(exc.exception),
        )

    def test_zsk_policy_max_bundle_overlap(self):
        """ Test two bundles with too little overlap (against ZSK policy) """
        bundle1, bundle2, = self._get_two_bundles(
            bundle1_inception="2019-01-01T00:00:00",
            bundle1_expiration="2019-01-22T00:00:00",
            bundle2_inception="2019-01-05T00:00:00",
            bundle2_expiration="2019-01-28T00:00:00",
        )
        xml = self._make_request(bundle1=bundle1, bundle2=bundle2)
        request = request_from_xml(xml)
        policy = replace(
            self.policy,
            check_bundle_intervals=False,  # want to test against ZSK policy, not KSK policy
            check_cycle_length=False,  # want to test against ZSK policy, not KSK policy
        )
        with self.assertRaises(KSR_POLICY_SIG_OVERLAP_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            'Bundle "id=test-2 2019-01-05->2019-01-28" overlap 17 days with '
            '"id=test-1 2019-01-01->2019-01-22" is > claimed maximum 12 days',
            str(exc.exception),
        )

    def test_request_with_one_day_overlap_problem(self):
        """ Test that the _make_request function produces a basically correct KSR """
        bundle1, bundle2, = self._get_two_bundles(
            bundle1_inception="2019-01-01T00:00:00",
            bundle1_expiration="2019-01-22T00:00:00",
            bundle2_inception="2019-01-14T00:00:00",
            bundle2_expiration="2019-02-04T00:00:00",
        )
        xml = self._make_request(bundle1=bundle1, bundle2=bundle2)
        request = request_from_xml(xml)
        policy = replace(
            self.policy,
            check_bundle_intervals=False,  # want to test against ZSK policy, not KSK policy
            check_cycle_length=False,  # want to test against ZSK policy, not KSK policy
        )
        with self.assertRaises(KSR_POLICY_SIG_OVERLAP_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            'Bundle "id=test-2 2019-01-14->2019-02-04" overlap 8 days with '
            '"id=test-1 2019-01-01->2019-01-22" is < claimed minimum 9 days',
            str(exc.exception),
        )

        # test that the check can be disabled
        policy = replace(
            self.policy,
            check_bundle_overlap=False,
            max_bundle_interval=duration_to_timedelta("P13D"),
        )
        self.assertTrue(validate_request(request, policy))

    def test_wrong_number_of_bundles(self):
        """ Test with two bundles where three was expected """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, num_keys_per_bundle=[1, 1, 1])
        with self.assertRaises(KSR_POLICY_KEYS_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Can't check number of keys per bundle for a KSR with 2 bundles",
            str(exc.exception),
        )

    def test_wrong_number_of_keys_in_a_bundle(self):
        """ Test with one key in a bundle where two was expected """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, num_keys_per_bundle=[2, 1])
        with self.assertRaises(KSR_POLICY_KEYS_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual("Bundle #1/test-1 has 1 keys, not 2", str(exc.exception))

    def test_wrong_total_number_of_keys(self):
        """ Test with one key where two different keys were expected """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, num_different_keys_in_all_bundles=2)
        with self.assertRaises(KSR_POLICY_KEYS_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Unacceptable number of key sets in request test, (1 keys instead of 2)",
            str(exc.exception),
        )

    def test_too_short_signature_validity(self):
        """ Test two bundles with too short signature validity (against ZSK policy) """
        bundle1, bundle2, = self._get_two_bundles(
            bundle1_inception="2019-01-01T00:00:00",
            bundle1_expiration="2019-01-22T00:00:00",
            bundle2_inception="2019-01-02T00:00:00",
            bundle2_expiration="2019-01-10T00:00:00",
        )
        xml = self._make_request(bundle1=bundle1, bundle2=bundle2)
        request = request_from_xml(xml)
        policy = replace(
            self.policy, check_bundle_intervals=False, check_cycle_length=False,
        )
        with self.assertRaises(KSR_POLICY_SIG_VALIDITY_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Bundle validity 8 days < claimed min_signature_validity 21 days (in bundle test-2)",
            str(exc.exception),
        )

    def test_too_long_signature_validity(self):
        """ Test two bundles with too long signature validity (against ZSK policy) """
        bundle1, bundle2, = self._get_two_bundles(
            bundle1_inception="2019-01-01T00:00:00",
            bundle1_expiration="2019-01-22T00:00:00",
            bundle2_inception="2019-01-12T00:00:00",
            bundle2_expiration="2019-06-02T00:00:00",
        )
        xml = self._make_request(bundle1=bundle1, bundle2=bundle2)
        request = request_from_xml(xml)
        policy = replace(
            self.policy,
            check_bundle_intervals=False,  # want to test against ZSK policy, not KSK policy
            check_cycle_length=False,  # want to test against ZSK policy, not KSK policy
        )
        with self.assertRaises(KSR_POLICY_SIG_VALIDITY_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Bundle validity 141 days > claimed max_signature_validity 21 days (in bundle test-2)",
            str(exc.exception),
        )

    def test_min_bundle_interval(self):
        """ Test two bundles with too low interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, min_bundle_interval=duration_to_timedelta("P15D"))
        with self.assertRaises(KSR_POLICY_BUNDLE_INTERVAL_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Bundle #2 (test-2) interval (11 days) less than minimum acceptable interval 15 days",
            str(exc.exception),
        )

    def test_max_bundle_interval(self):
        """ Test two bundles with too large interval """
        xml = self._make_request()
        request = request_from_xml(xml)
        policy = replace(self.policy, max_bundle_interval=duration_to_timedelta("P9D"))
        with self.assertRaises(KSR_POLICY_BUNDLE_INTERVAL_Violation) as exc:
            validate_request(request, policy)
        self.assertEqual(
            "Bundle #2 (test-2) interval (11 days) greater than maximum acceptable interval 9 days",
            str(exc.exception),
        )

        # test that the check can be disabled
        policy = replace(self.policy, check_bundle_intervals=False)
        self.assertTrue(validate_request(request, policy))
