import os
import unittest
import pkg_resources

from kskm.common.config import get_config
from kskm.skr import response_from_xml, skr_to_xml, load_skr, get_response_policy
from kskm.skr.validate import validate_response


class TestParseRealSKRs(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')
        self.policy_fn = os.path.join(self.data_dir, 'response_policy.yaml')

    def test_recreate_2018_q1_0(self):
        """ Test a parse->output->parse cycle with skr-root-2018-q1-0-d_to_e.xml """
        fn = os.path.join(self.data_dir, 'skr-root-2018-q1-0-d_to_e.xml')
        policy = get_response_policy(self.policy_fn, get_config(None))

        skr = load_skr(fn, policy)
        self.assertEqual(skr.id, '4fe9bb10-6f6b-4503-8575-7824e2d66925')

        new_xml = skr_to_xml(skr)
        new_skr = response_from_xml(new_xml)
        validate_response(new_skr, policy)

        # compare larger and larger parts, to get better indications of the
        # whereabouts of issues
        self.assertEqual(new_skr.id, '4fe9bb10-6f6b-4503-8575-7824e2d66925')

        self.assertEqual(skr.zsk_policy, new_skr.zsk_policy)
        self.assertEqual(skr.ksk_policy, new_skr.ksk_policy)

        for idx in range(len(skr.bundles)):
            self.assertEqual(skr.bundles[idx].id, new_skr.bundles[idx].id)
            self.assertEqual(skr.bundles[idx], new_skr.bundles[idx])

        self.assertEqual(skr.bundles, new_skr.bundles)

        self.assertEqual(skr, new_skr)
