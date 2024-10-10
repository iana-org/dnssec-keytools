import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from kskm.common.config import get_config
from kskm.common.integrity import sha2wordlist
from kskm.signer import output_skr_xml
from kskm.skr import load_skr, response_from_xml, skr_to_xml
from kskm.skr.data import Response
from kskm.skr.validate import validate_response


class TestParseRealSKRs(unittest.TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")

        fn = self.data_dir.joinpath("skr-root-2018-q1-0-d_to_e.xml")
        config = get_config(filename=None)
        policy = config.response_policy

        skr = load_skr(fn, policy)
        self.assertEqual(skr.id, "4fe9bb10-6f6b-4503-8575-7824e2d66925")

        self.skr_filename = fn
        self.skr = skr
        self.policy = policy

    def test_recreate_2018_q1_0(self) -> None:
        """Test a parse->output->parse cycle with skr-root-2018-q1-0-d_to_e.xml"""

        skr: Response = self.skr

        new_xml = skr_to_xml(skr)
        new_skr = response_from_xml(new_xml)
        validate_response(new_skr, self.policy)

        # compare larger and larger parts, to get better indications of the
        # whereabouts of issues
        self.assertEqual(new_skr.id, "4fe9bb10-6f6b-4503-8575-7824e2d66925")

        self.assertEqual(skr.zsk_policy, new_skr.zsk_policy)
        self.assertEqual(skr.ksk_policy, new_skr.ksk_policy)

        for idx in range(len(skr.bundles)):
            self.assertEqual(skr.bundles[idx].id, new_skr.bundles[idx].id)
            self.assertEqual(skr.bundles[idx], new_skr.bundles[idx])

        self.assertEqual(skr.bundles, new_skr.bundles)

        self.assertEqual(skr, new_skr)

    @patch("builtins.print")
    def test_output_skr_xml_print(self, mock: MagicMock) -> None:
        """Test the 'just print' mode of output_skr_xml"""
        output_skr_xml(self.skr, output_filename=None)

        expected = skr_to_xml(self.skr)
        mock.assert_called_once_with(expected)

    def test_output_skr_xml_write_to_file(self) -> None:
        """Test that the expected content is written to a (mocked) file"""
        test_fn = Path("mocked_file.skr")
        with patch("kskm.signer.open", mock_open()) as mock:
            output_skr_xml(self.skr, output_filename=test_fn, log_contents=True)

        expected = skr_to_xml(self.skr).encode()
        mock.assert_called_once_with(test_fn, "wb")
        mock().write.assert_called_once_with(expected)

    def test_sha2wordlist(self) -> None:
        """Test generation of PGP word list (and SHA-256 checksum) of content"""
        hexdigest, words = sha2wordlist(b"test")
        assert hexdigest == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

        expected = [
            "quota",
            "letterhead",
            "stagnate",
            "inventive",
            "newborn",
            "disbelief",
            "klaxon",
            "glossary",
            "pupil",
            "combustion",
            "Trojan",
            "Orlando",
            "solo",
            "existence",
            "stagnate",
            "bifocals",
            "reform",
            "rebellion",
            "dropper",
            "bravado",
            "briefcase",
            "armistice",
            "miser",
            "Chicago",
            "stairway",
            "filament",
            "glucose",
            "bifocals",
            "ruffled",
            "upcoming",
            "allow",
            "antenna",
        ]
        assert words == expected
