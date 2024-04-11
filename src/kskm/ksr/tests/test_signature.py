import os
from hashlib import sha256
from unittest import TestCase

import pkg_resources

from kskm.common.signature import make_raw_rrsig
from kskm.ksr import request_from_xml


class TestBundle_to_hashdigest(TestCase):
    def setUp(self):
        """Prepare test instance"""
        self.data_dir = pkg_resources.resource_filename(__name__, "data")

    def test_bundle_to_hashdigest(self):
        """Test hash computation of a single well-known bundle"""
        fn = "ksr-root-2009-q4-2.xml"
        fn = os.path.join(self.data_dir, fn)
        with open(fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        rrsig = make_raw_rrsig(ksr.bundles[0].signatures.pop(), ksr.bundles[0].keys)
        got = sha256(rrsig).hexdigest()
        expected = "6d754a22ae7bbf90a2d737dcca85a5dc3b3f8561dc4e48be90ef1ff78d1077a7"
        self.assertEqual(expected, got)
