import os
import unittest

import pkg_resources

from kskm.common.config import get_config
from kskm.skr import load_skr, response_from_xml


class TestParseRealSKRs(unittest.TestCase):
    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, "data")
        self.policy_fn = os.path.join(self.data_dir, "response_policy.yaml")

    def test_parse_skr_root_2018_q1_0_d_to_e(self):
        """ Test parsing skr-root-2018-q1-0-d_to_e.xml """
        fn = os.path.join(self.data_dir, "skr-root-2018-q1-0-d_to_e.xml")
        with open(fn, "r") as fd:
            xml = fd.read()
        skr = response_from_xml(xml)
        self.assertEqual("4fe9bb10-6f6b-4503-8575-7824e2d66925", skr.id)
        self.assertEqual(".", skr.domain)
        self.assertIsNone(skr.timestamp)
        # There are other test cases covering parts of the parsing in detail, so
        # here we only do cursory checks of the high level. Comparing 'ksr' with
        # a complete 'Request' instance would make it too rigid, at least at this
        # point in development.
        self.assertEqual(10 * 86400, skr.zsk_policy.publish_safety.total_seconds())
        bundle_ids = sorted([this.id for this in skr.bundles])
        expected_ids = sorted(
            [
                "09533c09-fbe7-4525-ad66-f407231b9568",
                "0a8f7774-3bd3-4702-a923-f1d73f653bd6",
                "3c49645b-fd2b-4c7a-8a97-d1f40406bed9",
                "3da474e2-295e-4343-8254-cd7283dbb84a",
                "4c05c9b8-a7c4-46b7-a4f8-737a5261f09b",
                "93db5926-731c-4153-ad35-bf62136e2dbe",
                "a63610d0-8ad3-41dc-aa3c-d8cd45c63f97",
                "bf4e1b34-b469-4dee-86df-0cfe867bbe5c",
                "facc4d74-8395-4c18-a887-323269b264d6",
            ]
        )
        self.assertEqual(expected_ids, bundle_ids)

    def test_parse_2018_q1_0(self):
        """ Test loading and validating skr-root-2018-q1-0-d_to_e.xml """
        fn = os.path.join(self.data_dir, "skr-root-2018-q1-0-d_to_e.xml")
        config = get_config(None)
        skr = load_skr(fn, config.response_policy)
        self.assertEqual(skr.id, "4fe9bb10-6f6b-4503-8575-7824e2d66925")

    def test_skr_log_contents_basics(self):
        """ Test logging SKR loading """
        fn = os.path.join(self.data_dir, "skr-root-2018-q1-0-d_to_e.xml")
        config = get_config(None)
        skr = load_skr(fn, config.response_policy, log_contents=True)
        self.assertEqual(skr.id, "4fe9bb10-6f6b-4503-8575-7824e2d66925")
