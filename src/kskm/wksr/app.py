"""Web app generator."""

import logging

import yaml

from kskm.common.config_wksr import WKSR_Config, WKSR_Templates

from .server import DEFAULT_TEMPLATES_CONFIG, generate_app

DEFAULT_CONFIG = "wksr.yaml"

logging.basicConfig(level=logging.INFO)

with open(DEFAULT_CONFIG) as fp:
    _config = yaml.safe_load(fp.read())

config = WKSR_Config.from_dict(_config)
if not config.templates:
    config.templates = WKSR_Templates.from_dict(DEFAULT_TEMPLATES_CONFIG)

application = generate_app(config)
