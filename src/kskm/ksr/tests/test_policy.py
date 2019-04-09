import os
import unittest

import pkg_resources

from kskm.ksr.policy import RequestPolicy, policy_from_file


class TestRequestPolicy(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')

    def test_load_request_policy(self):
        """ Test loading the request policy from file """
        fn = os.path.join(self.data_dir, 'request_policy.yaml')
        p = policy_from_file(fn)
        self.assertTrue(p.validate_signatures)

    def test_unknown_data(self):
        """ Test creating a policy from unknown data """
        data = {'UNKNOWN': 'just testing'}
        with self.assertRaises(TypeError):
            RequestPolicy.from_dict(data)

    def test_defaults(self):
        """ Test creating a policy with the default values """
        p = RequestPolicy.from_dict({})
        self.assertTrue(p.validate_signatures)
