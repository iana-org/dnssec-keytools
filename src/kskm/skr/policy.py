"""Dataclass and code to load a response policy from file/object."""
import yaml
import logging

from typing import Optional

from dataclasses import dataclass

from kskm.common.data import Policy
from kskm.common.config import ConfigType


__author__ = 'ft'


logger = logging.getLogger(__name__)


# TODO: ResponsePolicy is really both KSR and SKR policy
@dataclass(frozen=True)
class ResponsePolicy(Policy):
    """Validation parameters for SKRs."""

    num_bundles: int = 9
    validate_signatures: bool = True


def policy_from_file(fn: str) -> ResponsePolicy:
    """
    Load a response policy from a YAML file.

    The file contents translates directly into a ResponsePolicy instance, so e.g.:

    ---
    response:
        must_have_bundles: False
        validate_signatures: True
    """
    with open(fn) as fd:
        data = yaml.safe_load(fd)
    if 'response_policy' not in data:
        raise RuntimeError('Policy file {} has no "response" in it'.format(fn))
    try:
        return ResponsePolicy.from_dict(data['response_policy'])
    except TypeError:
        logger.exception('Failed loading response policy from file {}'.format(fn))
        raise


def get_response_policy(fn: Optional[str], config: ConfigType) -> ResponsePolicy:
    """Load a response policy from config, a YAML file, or return a default policy."""
    if config is not None and 'response_policy' in config:
        return ResponsePolicy.from_dict(config['response_policy'])
    if fn is not None:
        return policy_from_file(fn)
    # Return a default response policy
    return ResponsePolicy()
