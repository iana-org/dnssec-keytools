"""Test configuration schema validation using example config file"""

import os
import unittest
from tempfile import mkstemp

import pkg_resources
import yaml

import voluptuous.humanize
from kskm.common.config_schema import (KSRSIGNER_CONFIG_SCHEMA,
                                       WKSR_CONFIG_SCHEMA)

CONFIG_DIR = pkg_resources.resource_filename(__name__, '../../../../config')


class TestConfigSchema(unittest.TestCase):

    def test_ksrsigner_example_config(self):
        """Test ksrsigner example config"""
        _, file_placeholder = mkstemp()
        with open(CONFIG_DIR + '/ksrsigner.yaml') as input_file:
            config = yaml.safe_load(input_file)
        config['hsm']['softhsm']['module'] = file_placeholder
        config['hsm']['aep']['module'] = file_placeholder
        config['filenames']['previous_skr'] = file_placeholder
        config['filenames']['input_ksr'] = file_placeholder
        config['filenames']['output_skr'] = file_placeholder
        voluptuous.humanize.validate_with_humanized_errors(config, KSRSIGNER_CONFIG_SCHEMA)
        os.unlink(file_placeholder)

    def test_wksr_example_config(self):
        """Test wksr example config"""
        _, file_placeholder = mkstemp()
        with open(CONFIG_DIR + '/wksr.yaml') as input_file:
            config = yaml.safe_load(input_file)
        config['tls']['cert'] = file_placeholder
        config['tls']['key'] = file_placeholder
        config['tls']['ca_cert'] = file_placeholder
        config['ksr']['ksrsigner_configfile'] = file_placeholder
        config['templates']['upload'] = file_placeholder
        config['templates']['result'] = file_placeholder
        config['templates']['email'] = file_placeholder
        voluptuous.humanize.validate_with_humanized_errors(config, WKSR_CONFIG_SCHEMA)
        os.unlink(file_placeholder)


if __name__ == '__main__':
    unittest.main()
