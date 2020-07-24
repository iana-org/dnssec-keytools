"""Web app generator."""

import logging

import yaml

from .server import generate_app

DEFAULT_CONFIG = "wksr.yaml"

logging.basicConfig(level=logging.INFO)

config = yaml.load(open(DEFAULT_CONFIG).read(), Loader=yaml.SafeLoader)
application = generate_app(config)
