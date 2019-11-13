"""Config validation schema."""

from datetime import datetime

from voluptuous import (All, Any, Email, IsFile, Match, Range, Required, Schema)

from kskm.common.data import AlgorithmDNSSEC

HSM_SCHEMA = Schema({
    Required('module'): str,
    'pin': Schema(Any(str, int)),
    'so_pin': Schema(Any(str, int)),
    'env': dict
})

RSA_SIZE = All(int, Range(min=1, max=65535))
RSA_EXPONENT = All(int, Range(min=1))
HEXDIGEST = Match(r'[0-9a-fA-F]+')

KEY_SCHEMA = Schema({
    'description': str,
    'label': str,
    'key_tag': All(int, Range(min=0, max=65535)),
    'algorithm': Any(*[x.name for x in AlgorithmDNSSEC]),
    'rsa_size': RSA_SIZE,
    'rsa_exponent': RSA_EXPONENT,
    'valid_from': datetime,
    'valid_until': datetime,
    'ds_sha256': HEXDIGEST,
})

REQUEST_POLICY_SCHEMA = Schema({
    'warn_instead_of_fail': bool
})

REQUEST_POLICY_SCHEMA = REQUEST_POLICY_SCHEMA.extend({
    'acceptable_domains': Schema([str]),
    'num_bundles': All(int, Range(min=1)),
    'validate_signatures': bool,
    'keys_match_zsk_policy': bool,
    'rsa_exponent_match_zsk_policy': bool,
    'check_bundle_overlap': bool,
    'signature_validity_match_zsk_policy': bool,
    'signature_algorithms_match_zsk_policy': bool,
    'check_keys_match_ksk_operator_policy': bool,
    'acceptable_key_set_lengths': Schema([int]),
    'signature_check_expire_horizon': bool,
    'signature_horizon_days': int,
    'check_chain_keys': bool,
    'check_chain_overlap': bool,
    'approved_algorithms': Schema([str]),
    'rsa_approved_exponents': Schema([RSA_EXPONENT]),
    'rsa_approved_key_sizes': Schema([RSA_SIZE]),
})

RESPONSE_POLICY_SCHEMA = REQUEST_POLICY_SCHEMA.extend({
    'num_bundles': All(int, Range(min=1)),
    'validate_signatures': bool,
})

KSK_POLICY_SCHEMA = Schema({
    'signers_name': str,
    'publish_safety': str,
    'retire_safety': str,
    'max_signature_validity': str,
    'min_signature_validity': str,
    'max_validity_overlap': str,
    'min_validity_overlap': str,
    'ttl': All(int, Range(min=0)),
})

SCHEMA_SLOT_SCHEMA = Schema({
    'publish': Schema(Any(str, Schema([str]))),
    'sign': Schema(Any(str, Schema([str]))),
    'revoke': Schema(Any(str, Schema([str]))),
})

SCHEMA_SCHEMA = Schema({int: SCHEMA_SLOT_SCHEMA})

KSRSIGNER_CONFIG_SCHEMA = Schema({
    'hsm': Schema({str: HSM_SCHEMA}),
    'filenames': {
        'previous_skr': IsFile(),
        'input_ksr': IsFile(),
        'output_skr': IsFile(),
    },
    'keys': Schema({str: KEY_SCHEMA}),
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
        'client_whitelist': Schema([HEXDIGEST]),
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
        'smtp_server': str,
    })
})
