import os
import unittest
from pathlib import Path

from pydantic import ValidationError

from kskm.common.config import get_config
from kskm.common.config_misc import RequestPolicy


class TestRequestPolicy(unittest.TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")

    def test_load_request_policy(self) -> None:
        """Test loading the request policy from file"""
        fn = self.data_dir.joinpath("request_policy.yaml")
        config = get_config(fn)
        self.assertTrue(config.request_policy.validate_signatures)

    def test_unknown_data(self) -> None:
        """Test creating a policy from unknown data"""
        data = {"UNKNOWN": "just testing"}
        with self.assertRaises(ValidationError):
            RequestPolicy.model_validate(data)

    def test_defaults(self) -> None:
        """Test creating a policy with the default values"""
        p = RequestPolicy.model_validate({})
        self.assertTrue(p.validate_signatures)
