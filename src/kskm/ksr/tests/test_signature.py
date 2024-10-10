import os
from hashlib import sha256
from pathlib import Path
from unittest import TestCase

from kskm.common.signature import make_raw_rrsig
from kskm.ksr import request_from_xml


class TestBundle_to_hashdigest(TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")

    def test_bundle_to_hashdigest(self) -> None:
        """Test hash computation of a single well-known bundle"""
        fn = self.data_dir.joinpath("ksr-root-2009-q4-2.xml")
        with open(fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        rrsig = make_raw_rrsig(ksr.bundles[0].signatures.pop(), ksr.bundles[0].keys)
        got = sha256(rrsig).hexdigest()
        expected = "6d754a22ae7bbf90a2d737dcca85a5dc3b3f8561dc4e48be90ef1ff78d1077a7"
        self.assertEqual(expected, got)
