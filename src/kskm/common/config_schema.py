"""Config validation schema."""

from datetime import datetime

from voluptuous import All, Any, Email, IsFile, Match, Range, Required, Schema
from voluptuous.validators import DOMAIN_REGEX

from kskm.common.data import AlgorithmDNSSEC
from kskm.common.parse_utils import duration_to_timedelta


def iso8601_duration():
    """Validation ISO 8601 durations"""
    return lambda v: duration_to_timedelta(v)


HSM_SCHEMA = Schema({
    Required('module'): Schema(Any(IsFile(), Match(r'^\$\w+'))),
    'pin': Schema(Any(str, int)),
    'so_pin': Schema(Any(str, int)),
    'env': dict
})

KEY_NAME = Match(r'[\w_]+')
KEY_LABEL = Match(r'[\w_]+')
RSA_SIZE = All(int, Range(min=1, max=65535))
RSA_EXPONENT = All(int, Range(min=1))
HEX_DIGEST = Match(r'[0-9a-fA-F]+')
HOST_NAME = Match(DOMAIN_REGEX)
DOMAIN_NAME = Any('.', Match('\w+'), Match(DOMAIN_REGEX))
TTL = All(int, Range(min=0))

KEY_SCHEMA = Schema({
    'label': KEY_LABEL,
    'description': str,
    'key_tag': All(int, Range(min=0, max=65535)),
    'algorithm': Any(*[x.name for x in AlgorithmDNSSEC]),
    'rsa_size': RSA_SIZE,
    'rsa_exponent': RSA_EXPONENT,
    'valid_from': datetime,
    'valid_until': datetime,
    'ds_sha256': HEX_DIGEST,
})

REQUEST_POLICY_SCHEMA = Schema({
    'warn_instead_of_fail': bool
})

REQUEST_POLICY_SCHEMA = REQUEST_POLICY_SCHEMA.extend({
    'acceptable_domains': Schema([DOMAIN_NAME]),
    'num_bundles': All(int, Range(min=1)),
    'validate_signatures': bool,
    'keys_match_zsk_policy': bool,
    'rsa_exponent_match_zsk_policy': bool,
    'enable_unsupported_ecdsa': bool,

    'check_cycle_length': bool,
    'min_cycle_inception_length': iso8601_duration(),
    'max_cycle_inception_length': iso8601_duration(),
    'min_bundle_interval': iso8601_duration(),
    'max_bundle_interval': iso8601_duration(),

    'check_bundle_overlap': bool,
    'signature_validity_match_zsk_policy': bool,
    'signature_algorithms_match_zsk_policy': bool,
    'check_keys_match_ksk_operator_policy': bool,
    'num_keys_per_bundle': Schema([All(int, Range(min=1))]),
    'num_different_keys_in_all_bundles': All(int, Range(min=1)),
    'dns_ttl': TTL,
    'signature_check_expire_horizon': bool,
    'signature_horizon_days': All(int, Range(min=1)),

    'check_bundle_intervals': bool,
    'min_bundle_duration': iso8601_duration(),
    'max_bundle_duration': iso8601_duration(),
    'check_cycle_length': bool,
    'min_cycle_duration': iso8601_duration(),
    'max_cycle_duration': iso8601_duration(),
    'check_chain_keys': bool,
    'check_chain_keys_in_hsm': bool,
    'check_chain_overlap': bool,
    'approved_algorithms': Schema([str]),
    'rsa_approved_exponents': Schema([RSA_EXPONENT]),
    'rsa_approved_key_sizes': Schema([RSA_SIZE]),

    'check_keys_publish_safety': bool,
    'check_keys_retire_safety': bool,
})

RESPONSE_POLICY_SCHEMA = REQUEST_POLICY_SCHEMA.extend({
    'num_bundles': All(int, Range(min=1)),
    'validate_signatures': bool,
})

KSK_POLICY_SCHEMA = Schema({
    'signers_name': DOMAIN_NAME,
    'publish_safety': iso8601_duration(),
    'retire_safety': iso8601_duration(),
    'max_signature_validity': iso8601_duration(),
    'min_signature_validity': iso8601_duration(),
    'max_validity_overlap': iso8601_duration(),
    'min_validity_overlap': iso8601_duration(),
    'ttl': TTL,
})

SCHEMA_SLOT_SCHEMA = Schema({
    'publish': Schema(Any(KEY_NAME, Schema([KEY_NAME]))),
    'sign': Schema(Any(KEY_NAME, Schema([KEY_NAME]))),
    'revoke': Schema(Any(KEY_NAME, Schema([KEY_NAME]))),
})

SCHEMA_SLOT = All(int, Range(min=1))
SCHEMA_SCHEMA = Schema({SCHEMA_SLOT: SCHEMA_SLOT_SCHEMA})

KSRSIGNER_CONFIG_SCHEMA = Schema({
    'hsm': Schema({str: HSM_SCHEMA}),
    'filenames': {
        'previous_skr': IsFile(),
        'input_ksr': IsFile(),
        'output_skr': IsFile(),
    },
    'keys': Schema({KEY_NAME: KEY_SCHEMA}),
    'request_policy': REQUEST_POLICY_SCHEMA,
    'response_policy': RESPONSE_POLICY_SCHEMA,
    'ksk_policy': KSK_POLICY_SCHEMA,
    'schemas': Schema({str: SCHEMA_SCHEMA}),
})

WKSR_CONFIG_SCHEMA = Schema({
    'tls': Schema({
        'cert': IsFile(),
        'key': IsFile(),
        'ca_cert': IsFile(),
        'ciphers': Schema([str]),
        'require_client_cert': bool,
        'client_whitelist': Schema([HEX_DIGEST]),
    }),
    'ksr': Schema({
        'max_size': All(int, Range(min=0)),
        'content_type': str,
        'prefix': str,
        'ksrsigner_configfile': IsFile(),
    }),
    'templates': Schema({
        'upload': IsFile(),
        'result': IsFile(),
        'email': IsFile(),
    }),
    'notify': Schema({
        'from': Email(),
        'to': Email(),
        'subject': str,
        'smtp_server': HOST_NAME,
    })
})
