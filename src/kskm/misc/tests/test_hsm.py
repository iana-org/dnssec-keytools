import os
from pathlib import Path
from unittest import TestCase

from kskm.misc import hsm


class Test_load_hsmconfig(TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")
        self.config_fn = self.data_dir.joinpath("test.hsmconfig")

    def test_load_hsmconfig(self) -> None:
        """Test loading a properly formatted hsm config file"""
        cfg = hsm.load_hsmconfig(self.config_fn, {"HOME": "/test"})
        expected = {
            "KEYPER_LIBRARY_PATH": "/test/dnssec/ksr/AEP",
            "LD_LIBRARY_PATH": "/test/dnssec/ksr/AEP",
            "PKCS11_LIBRARY_PATH": "/test/dnssec/ksr/AEP/pkcs11.GCC4.0.2.so.4.07",
        }
        self.assertEqual(expected, cfg)

    def test_load_hsmconfig_os_defaults(self) -> None:
        """Test loading a properly formatted hsm config file"""
        os.environ["HOME"] = "/test"
        cfg = hsm.load_hsmconfig(self.config_fn)
        expected = {
            "KEYPER_LIBRARY_PATH": "/test/dnssec/ksr/AEP",
            "LD_LIBRARY_PATH": "/test/dnssec/ksr/AEP",
            "PKCS11_LIBRARY_PATH": "/test/dnssec/ksr/AEP/pkcs11.GCC4.0.2.so.4.07",
        }
        self.assertEqual(expected, cfg)

    def test_parse_hsmconfig_no_separator(self) -> None:
        """Test parsing line without separator (=)"""
        with self.assertRaises(ValueError):
            hsm.parse_hsmconfig(iter(["foo"]), Path("test data"), {"HOME": "/test"})

    def test_parse_hsmconfig_invalid_variable_value(self) -> None:
        """Test parsing line with value resolving to another value"""
        with self.assertRaises(ValueError):
            hsm.parse_hsmconfig(
                iter(["foo=$TEST"]), Path("test data"), {"TEST": "$TEST"}
            )

    def test_parse_hsmconfig_unknown_variable_value(self) -> None:
        """Test parsing line with unknown variable"""
        with self.assertRaises(RuntimeError):
            hsm.parse_hsmconfig(iter(["foo=$TEST"]), Path("test data"), {})

    def test_parse_hsmconfig_too_long(self) -> None:
        """Test parsing line with too many lines of config"""
        with self.assertRaises(RuntimeError):
            hsm.parse_hsmconfig(
                iter(["foo=TEST", "bar=yes"]), Path("test data"), {}, max_lines=1
            )
