"""Test configuration schema validation using example config file"""

# import os
import unittest

# from tempfile import mkstemp

# import voluptuous.error
# import voluptuous.humanize
# import yaml

# from kskm.common.config import ConfigurationError, get_config
# from kskm.common.config_schema import KSRSIGNER_CONFIG_SCHEMA, WKSR_CONFIG_SCHEMA

# CONFIG_DIR = os.path.join(os.path.dirname(__file__), "../../../../config")


# class TestConfigSchema(unittest.TestCase):
#     def test_ksrsigner_example_config(self) -> None:
#         """Test ksrsigner example config"""
#         _, file_placeholder = mkstemp()
#         with open(os.path.join(CONFIG_DIR, "ksrsigner.yaml")) as input_file:
#             config = yaml.safe_load(input_file)
#         config["hsm"]["softhsm"]["module"] = file_placeholder
#         config["hsm"]["aep"]["module"] = file_placeholder
#         config["filenames"]["previous_skr"] = file_placeholder
#         config["filenames"]["input_ksr"] = file_placeholder
#         config["filenames"]["output_skr"] = file_placeholder
#         voluptuous.humanize.validate_with_humanized_errors(
#             config, KSRSIGNER_CONFIG_SCHEMA
#         )
#         os.unlink(file_placeholder)

#     def test_ksrsigner_bad_config(self) -> None:
#         """Test ksrsigner example config"""
#         config = {"xyzzy": False}
#         with self.assertRaises(voluptuous.error.Error):
#             voluptuous.humanize.validate_with_humanized_errors(
#                 config, KSRSIGNER_CONFIG_SCHEMA
#             )

#     def test_loading_from_file(self) -> None:
#         _, config_fn = mkstemp()
#         _, file_placeholder = mkstemp()
#         with open(os.path.join(CONFIG_DIR, "ksrsigner.yaml")) as input_file:
#             config = yaml.safe_load(input_file)
#         config["hsm"]["softhsm"]["module"] = file_placeholder
#         config["hsm"]["aep"]["module"] = file_placeholder
#         config["filenames"]["previous_skr"] = file_placeholder
#         config["filenames"]["input_ksr"] = file_placeholder
#         config["filenames"]["output_skr"] = file_placeholder
#         with open(config_fn, "w") as fd:
#             yaml.dump(config, fd)
#         parsed_config = get_config(config_fn)
#         self.assertEqual(parsed_config.get_filename("input_ksr"), file_placeholder)
#         self.assertIsNone(parsed_config.get_filename("no_such_file"))
#         os.unlink(file_placeholder)
#         os.unlink(config_fn)

#     def test_loading_from_file_error_handling(self) -> None:
#         with self.assertRaises(ConfigurationError) as exc:
#             get_config(os.path.join(CONFIG_DIR, "ksrsigner.yaml"))
#         self.assertIn("Not a file for dictionary value", str(exc.exception))

#     def test_wksr_example_config(self) -> None:
#         """Test wksr example config"""
#         _, file_placeholder = mkstemp()
#         with open(os.path.join(CONFIG_DIR, "wksr.yaml")) as input_file:
#             config = yaml.safe_load(input_file)
#         config["tls"]["cert"] = file_placeholder
#         config["tls"]["key"] = file_placeholder
#         config["tls"]["ca_cert"] = file_placeholder
#         config["ksr"]["ksrsigner_configfile"] = file_placeholder
#         config["templates"]["upload"] = file_placeholder
#         config["templates"]["result"] = file_placeholder
#         config["templates"]["email"] = file_placeholder
#         voluptuous.humanize.validate_with_humanized_errors(config, WKSR_CONFIG_SCHEMA)
#         os.unlink(file_placeholder)

#     def test_wksr_bad_config(self) -> None:
#         """Test wksr example config"""
#         config = {"xyzzy": False}
#         with self.assertRaises(voluptuous.error.Error):
#             voluptuous.humanize.validate_with_humanized_errors(
#                 config, WKSR_CONFIG_SCHEMA
#             )

if __name__ == "__main__":
    unittest.main()
