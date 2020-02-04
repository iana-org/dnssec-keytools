import datetime
import logging
import os
import unittest
from dataclasses import replace

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.ksr import request_from_xml
from kskm.ksr.verify_bundles import KSR_BUNDLE_UNIQUE_Violation
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.ksr.verify_policy import KSR_POLICY_SAFETY_Violation
from kskm.signer.policy import check_last_skr_and_new_skr, check_skr_and_ksr
from kskm.signer.verify_chain import KSR_CHAIN_OVERLAP_Violation
from kskm.skr import response_from_xml

__author__ = "ft"


logger = logging.getLogger(__name__)


class Test_KSR_SKR_policy(unittest.TestCase):
    def setUp(self) -> None:
        # Initialise KSR and last SKR data structures
        self.data_dir = pkg_resources.resource_filename(__name__, "data")

        with open(os.path.join(self.data_dir, "ksr-root-2017-q2-0.xml")) as fd:
            self.ksr_xml = fd.read()
            self.ksr = request_from_xml(self.ksr_xml)

        with open(os.path.join(self.data_dir, "skr-root-2017-q1-0.xml")) as fd:
            self.skr_xml1 = fd.read()
            self.skr1 = response_from_xml(self.skr_xml1)

        with open(os.path.join(self.data_dir, "skr-root-2017-q2-0.xml")) as fd:
            self.skr_xml2 = fd.read()
            self.skr2 = response_from_xml(self.skr_xml2)

        with open(os.path.join(self.data_dir, "skr-root-2017-q3-0-c_to_d.xml")) as fd:
            self.skr_xml3 = fd.read()
            self.skr3 = response_from_xml(self.skr_xml3)

        self.policy = RequestPolicy()

    def test_last_skr_and_new_skr(self):
        """ Test with two consecutive SKRs from the archive """
        check_last_skr_and_new_skr(self.skr1, self.skr2, self.policy)

    def test_bad_skr_sequence(self):
        """ Test with two SKRs not adjacent to each other in time  """
        with self.assertRaises(KSR_POLICY_SAFETY_Violation):
            check_last_skr_and_new_skr(self.skr1, self.skr3, self.policy)

        # test turning off the check
        _policy = replace(self.policy, check_keys_publish_safety=False)
        check_last_skr_and_new_skr(self.skr1, self.skr3, _policy)

    def test_last_skr_and_new_skr_wrong_order(self):
        """ Test with two consecutive SKRs from the archive """
        with self.assertRaises(KSR_POLICY_SAFETY_Violation):
            check_last_skr_and_new_skr(self.skr2, self.skr1, self.policy)

    def test_key_missing_from_last_skr_last_bundle(self):
        """ Test removing the signing key from the last bundle of the previous SKR """
        # create local instance of skr1 to not mess with other tests
        skr1 = response_from_xml(self.skr_xml1)

        # verify check passes with unmodified skr1
        check_last_skr_and_new_skr(skr1, self.skr2, self.policy)

        last_bundle = replace(skr1.bundles[-1], keys=set())
        bundles = skr1.bundles
        bundles[-1] = last_bundle
        skr1 = replace(skr1, bundles=bundles)

        with self.assertRaises(KSR_POLICY_SAFETY_Violation):
            check_last_skr_and_new_skr(skr1, self.skr2, self.policy)

        # verify check can be disabled using configuration
        _policy = replace(self.policy, check_keys_publish_safety=False)
        check_last_skr_and_new_skr(skr1, self.skr2, _policy)

    def test_key_missing_from_new_skr_last_bundle(self):
        """ Test bad signing schema not adding key to the last bundle """
        # create local instance of skr2 to not mess with other tests
        skr2 = response_from_xml(self.skr_xml2)

        # verify check passes with unmodified skr2
        check_last_skr_and_new_skr(self.skr1, skr2, self.policy)

        last_bundle = replace(skr2.bundles[-1], keys=set())
        bundles = skr2.bundles
        bundles[-1] = last_bundle
        skr2 = replace(skr2, bundles=bundles)

        with self.assertRaises(KSR_POLICY_SAFETY_Violation) as exc:
            check_last_skr_and_new_skr(self.skr1, skr2, self.policy)

        # Check exact error message to differentiate from error in check_retire_safety
        self.assertEqual(
            "Key 19036/Kjqmt7v used to sign bundle #1 (dc1bc68c-b1c1-46f8-817f-ec893549f2be) in this SKR "
            "is not present in bundle #8 (dbd2a673-5ec5-4a72-9c02-11d48d27dc43)",
            str(exc.exception),
        )

        # verify check can be disabled using configuration
        _policy = replace(self.policy, check_keys_retire_safety=False)
        check_last_skr_and_new_skr(self.skr1, skr2, _policy)

    def test_key_removed_prematurely(self):
        """ Test bad signing schema not post-publishing a signing key long enough """
        # create local instance of skr2 to not mess with other tests
        skr2 = response_from_xml(self.skr_xml2)

        # verify check passes with unmodified skr2
        check_last_skr_and_new_skr(self.skr1, skr2, self.policy)

        first_bundle = replace(skr2.bundles[0], keys=set())
        bundles = skr2.bundles
        bundles[0] = first_bundle
        skr2 = replace(skr2, bundles=bundles)

        with self.assertRaises(KSR_POLICY_SAFETY_Violation) as exc:
            check_last_skr_and_new_skr(self.skr1, skr2, self.policy)

        # Check exact error message to differentiate from error from check_publish_safety
        self.assertEqual(
            "Key 19036/Kjqmt7v used to sign bundle c8753ecf-cbaf-4adc-902b-9f3e0861cc48 in the last SKR "
            "is not present in bundle dc1bc68c-b1c1-46f8-817f-ec893549f2be which expires < RetireSafety "
            "(28 days/2017-04-29 00:00:00+00:00) from this new SKRs first bundle inception "
            "(2017-04-01 00:00:00+00:00)",
            str(exc.exception),
        )


class Test_LastSKR_unique_ids(Test_KSR_SKR_policy):
    def test_real_ksr_and_last_skr(self):
        """ Test loading a real KSR and the produced SKR from the archives """
        check_skr_and_ksr(self.ksr, self.skr1, self.policy, p11modules=None)

    def test_ksr_and_last_skr_duplicate_id(self):
        """ Test that duplicate request/response IDs are detected """
        new_ksr = replace(self.ksr, id=self.skr1.id)
        with self.assertRaises(KSR_ID_Violation):
            check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)

    def test_repeated_bundle_id(self):
        """ Test that repeated bundle IDs are detected """
        ksr_bundles = self.ksr.bundles
        ksr_bundles[1] = replace(ksr_bundles[1], id=self.skr1.bundles[-1].id)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)
        with self.assertRaises(KSR_BUNDLE_UNIQUE_Violation):
            check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)


class Test_Chain(Test_KSR_SKR_policy):
    def test_timeline_gap(self):
        """ Test that a gap in the bundles timeline is detected """
        ksr_bundles = self.ksr.bundles
        last_expire = self.skr1.bundles[-1].expiration
        new_inception = last_expire + datetime.timedelta(days=1)
        ksr_bundles[0] = replace(ksr_bundles[0], inception=new_inception)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)
        with self.assertRaises(KSR_CHAIN_OVERLAP_Violation):
            check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)

    def test_timeline_too_small_overlap(self):
        """ Test that a too small overlap in the bundles timeline is detected """
        ksr_bundles = self.ksr.bundles
        last_expire = self.skr1.bundles[-1].expiration
        # first, set inception to the smallest value permitted by the KSR policy (this should work)
        new_inception = last_expire - self.ksr.zsk_policy.min_validity_overlap
        ksr_bundles[0] = replace(ksr_bundles[0], inception=new_inception)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)
        check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)

        # next, move inception back one more second
        new_inception = (
            last_expire
            - self.ksr.zsk_policy.min_validity_overlap
            + datetime.timedelta(seconds=1)
        )
        ksr_bundles[0] = replace(ksr_bundles[0], inception=new_inception)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)

        with self.assertRaises(KSR_CHAIN_OVERLAP_Violation):
            check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)

    def test_timeline_too_large_overlap(self):
        """ Test that a too large overlap in the bundles timeline is detected """
        ksr_bundles = self.ksr.bundles
        last_inception = self.skr1.bundles[-1].inception
        # first, set inception to the largest value permitted by the KSR policy (this should work)
        new_inception = last_inception + self.ksr.zsk_policy.max_validity_overlap
        ksr_bundles[0] = replace(ksr_bundles[0], inception=new_inception)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)
        check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)

        # next, move inception back one more second
        new_inception = (
            last_inception
            + self.ksr.zsk_policy.min_validity_overlap
            - datetime.timedelta(seconds=1)
        )
        ksr_bundles[0] = replace(ksr_bundles[0], inception=new_inception)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)

        with self.assertRaises(KSR_CHAIN_OVERLAP_Violation):
            check_skr_and_ksr(new_ksr, self.skr1, self.policy, p11modules=None)
