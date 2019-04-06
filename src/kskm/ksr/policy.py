"""Dataclass and code to load a request policy from file/object."""
import logging
from dataclasses import dataclass, field, replace
from typing import List, Optional

import yaml

from kskm.common.config import ConfigType
from kskm.common.data import Policy

__author__ = 'ft'


logger = logging.getLogger(__name__)


# TODO: How to handle different versions of this policy over time?
@dataclass(frozen=True)
class RequestPolicy(Policy):
    """Configuration knobs for validating KSRs."""

    # Verify KSR header parameters
    acceptable_domains: List[str] = field(default_factory=lambda: ['.'])

    # Verify KSR bundles
    num_bundles: int = 9
    validate_signatures: bool = True
    keys_match_zsk_policy: bool = True
    rsa_exponent_match_zsk_policy: bool = True

    # Verify KSR policy parameters
    check_bundle_overlap: bool = True
    signature_algorithms_match_zsk_policy: bool = True
    approved_algorithms: List[str] = field(default_factory=lambda: ['RSASHA256'])
    rsa_approved_exponents: List[int] = field(default_factory=lambda: [3, 65537])
    rsa_approved_key_sizes: List[int] = field(default_factory=lambda: [2048])
    signature_validity_match_zsk_policy: bool = True
    check_keys_match_ksk_operator_policy: bool = True
    # TODO: Only have 3 as acceptable key set length, and require special policy for special case?
    acceptable_key_set_lengths: List[int] = field(default_factory=lambda: [2, 3])
    dns_ttl: int = 0  # if this is 0, the config value ksk_policy.ttl will be used instead

    # Verify KSR/SKR chaining
    check_request_daisy_chain: bool = True
    # TODO: match policy timers
    # TODO: match policy algorithms (match against acceptable)
    # TODO: protocol, flags match
    # TODO: TTL limit
    # TODO: rsa_approved_exponents: [3, 65537]
    # TODO: rsa_approved_keysize: [2048]


def policy_from_file(fn: str) -> RequestPolicy:
    """
    Load a request policy from a YAML file.

    The file contents translates directly into a RequestPolicy instance, so e.g.:

    ---
    request:
        must_have_bundles: False
        validate_signatures: True
    """
    with open(fn) as fd:
        data = yaml.safe_load(fd)
    if 'request_policy' not in data:
        raise RuntimeError('Policy file {} has no "request" in it'.format(fn))
    try:
        return RequestPolicy.from_dict(data['request_policy'])
    except TypeError:
        logger.exception('Failed loading request policy from file {}'.format(fn))
        raise


def get_request_policy(fn: Optional[str], config: ConfigType) -> RequestPolicy:
    """Load a request policy from config, a YAML file, or return a default policy."""
    if 'request_policy' in config:
        policy = RequestPolicy.from_dict(config['request_policy'])
    elif fn is not None:
        policy = policy_from_file(fn)
    else:
        # Use a default request policy
        policy = RequestPolicy()
    if policy.dns_ttl == 0:
        # Replace with the value configured to be used when signing the bundles
        policy = replace(policy, dns_ttl=config['ksk_policy']['ttl'])
    return policy
