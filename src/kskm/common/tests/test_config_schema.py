"""Test configuration schema validation using example config file"""

import os
import unittest
from pathlib import Path
from tempfile import mkstemp

import pytest
import yaml
from pydantic import ValidationError

from kskm.common.config import KSKMConfig, get_config
from kskm.common.config_schema import WKSRConfig

CONFIG_DIR = Path(os.path.dirname(__file__), "../../../../config")


class TestConfigSchema(unittest.TestCase):
    def test_ksrsigner_example_config(self) -> None:
        """Test ksrsigner example config"""
        _, file_placeholder = mkstemp()
        with open(CONFIG_DIR.joinpath("ksrsigner.yaml")) as input_file:
            config = yaml.safe_load(input_file)
        config["hsm"]["softhsm"]["module"] = file_placeholder
        config["hsm"]["aep"]["module"] = file_placeholder
        config["filenames"]["previous_skr"] = file_placeholder
        config["filenames"]["input_ksr"] = file_placeholder
        config["filenames"]["output_skr"] = file_placeholder

        _loaded = KSKMConfig.from_dict(config)
        os.unlink(file_placeholder)

        assert _loaded.hsm["softhsm"].pin == 123456

    def test_ksrsigner_bad_config(self) -> None:
        """Test ksrsigner example config"""
        config = {"xyzzy": False}
        with pytest.raises(ValidationError):
            KSKMConfig.from_dict(config)

    def test_loading_from_file(self) -> None:
        _, config_fn = mkstemp()
        _, file_placeholder = mkstemp()
        with open(os.path.join(CONFIG_DIR, "ksrsigner.yaml")) as input_file:
            config = yaml.safe_load(input_file)
        config["hsm"]["softhsm"]["module"] = file_placeholder
        config["hsm"]["aep"]["module"] = file_placeholder
        config["filenames"]["previous_skr"] = file_placeholder
        config["filenames"]["input_ksr"] = file_placeholder
        config["filenames"]["output_skr"] = file_placeholder
        with open(config_fn, "w") as fd:
            yaml.dump(config, fd)
        parsed_config = get_config(config_fn)
        os.unlink(file_placeholder)
        os.unlink(config_fn)
        self.assertEqual(parsed_config.filenames.input_ksr, Path(file_placeholder))

    def test_loading_from_file_error_handling(self) -> None:
        with pytest.raises(ValidationError, match="Path does not point to a file"):
            get_config(os.path.join(CONFIG_DIR, "ksrsigner.yaml"))

    def test_wksr_example_config(self) -> None:
        """Test wksr example config"""
        _, file_placeholder = mkstemp()
        with open(os.path.join(CONFIG_DIR, "wksr.yaml")) as input_file:
            config = yaml.safe_load(input_file)
        config["tls"]["cert"] = file_placeholder
        config["tls"]["key"] = file_placeholder
        config["tls"]["ca_cert"] = file_placeholder
        config["ksr"]["ksrsigner_configfile"] = file_placeholder
        config["templates"]["upload"] = file_placeholder
        config["templates"]["result"] = file_placeholder
        config["templates"]["email"] = file_placeholder

        _loaded = WKSRConfig.model_validate(config)
        os.unlink(file_placeholder)

        assert _loaded.notify is not None and _loaded.notify.subject == "Hello"

    def test_wksr_bad_config(self) -> None:
        """Test wksr example config"""
        config = {"xyzzy": False}
        with pytest.raises(ValidationError):
            WKSRConfig.model_validate(config)


if __name__ == "__main__":
    unittest.main()
