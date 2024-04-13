"""Web app generator."""

import logging

import yaml

from .server import generate_app

DEFAULT_CONFIG = "wksr.yaml"

logging.basicConfig(level=logging.INFO)

with open(DEFAULT_CONFIG) as fp:
        config = yaml.load(fp.read(), Loader=yaml.SafeLoader)

application = generate_app(config)
