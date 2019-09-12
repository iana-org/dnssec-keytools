import os
import unittest
from dataclasses import replace

import pkg_resources

from kskm.common.config_misc import RequestPolicy
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.ksr import request_from_xml
from kskm.ksr.data import RequestBundle, Request
from kskm.ksr.verify_bundles import KSR_BUNDLE_UNIQUE_Violation
from kskm.ksr.verify_header import KSR_ID_Violation
from kskm.signer.policy import check_skr_and_ksr
from kskm.skr import response_from_xml

__author__ = 'ft'


class Test_LastSKR_unique_ids(unittest.TestCase):

    def setUp(self) -> None:
        # Initialise KSR and last SKR data structures
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')

        with open(os.path.join(self.data_dir, 'ksr-root-2017-q2-0.xml')) as fd:
            ksr_xml = fd.read()
            self.ksr = request_from_xml(ksr_xml)

        with open(os.path.join(self.data_dir, 'skr-root-2017-q1-0.xml')) as fd:
            last_skr_xml = fd.read()
            self.last_skr = response_from_xml(last_skr_xml)

        self.policy = RequestPolicy()

    def test_real_ksr_and_last_skr(self):
        """ Test loading a real KSR and the produced SKR from the archives """
        check_skr_and_ksr(self.ksr, self.last_skr, self.policy)

    def test_ksr_and_last_skr_duplicate_id(self):
        """ Test that duplicate request/response IDs are detected """
        new_ksr = replace(self.ksr, id=self.last_skr.id)
        with self.assertRaises(KSR_ID_Violation):
            check_skr_and_ksr(new_ksr, self.last_skr, self.policy)

    def test_repeated_bundle_id(self):
        """ Test that repeated bundle IDs are detected """
        ksr_bundles = self.ksr.bundles
        ksr_bundles[1] = replace(ksr_bundles[1], id=self.last_skr.bundles[-1].id)
        new_ksr = replace(self.ksr, bundles=ksr_bundles)
        with self.assertRaises(KSR_BUNDLE_UNIQUE_Violation):
            check_skr_and_ksr(new_ksr, self.last_skr, self.policy)

