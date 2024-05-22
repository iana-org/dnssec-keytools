"""Web app generator."""

import logging

import yaml

from kskm.common.config_wksr import WKSR_Config
from kskm.server import generate_app

DEFAULT_CONFIG = "wksr.yaml"

logging.basicConfig(level=logging.INFO)

with open(DEFAULT_CONFIG) as fp:
    _config = yaml.safe_load(fp.read())

config = WKSR_Config.from_dict(_config)

application = generate_app(config)
