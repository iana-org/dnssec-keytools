from datetime import datetime
import yaml
import voluptuous.humanize
from voluptuous import Schema, Required, All, Length, Range, Object, IsFile, Any, Literal, Email, Match

from kskm.common.data import AlgorithmDNSSEC

hsm_schema = Schema({
    Required('module'): str,
    'pin': Schema(Any(str, int)),
    'so_pin': Schema(Any(str, int)),
    'env': dict
})

rsa_size = All(int, Range(min=1, max=65535))
rsa_exponent = All(int, Range(min=1))
hexdigest = Match(r'[0-9a-fA-F]+')

key_schema = Schema({
    'description': str,
    'label': str,
    'key_tag': All(int, Range(min=0, max=65535)),
    'algorithm': Any(*[x.name for x in AlgorithmDNSSEC]),
    'rsa_size': rsa_size,
    'rsa_exponent': rsa_exponent,
    'valid_from': datetime,
    'valid_until': datetime,
    'ds_sha256': hexdigest,
})

request_policy_schema = Schema({
    'warn_instead_of_fail': bool
})

request_policy_schema = request_policy_schema.extend({
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
    'rsa_approved_exponents': Schema([rsa_exponent]),
    'rsa_approved_key_sizes': Schema([rsa_size]),
})

response_policy_schema = request_policy_schema.extend({
    'num_bundles': All(int, Range(min=1)),
    'validate_signatures': bool,
})

ksk_policy_schema = Schema({
    'signers_name': str,
    'publish_safety': str,
    'retire_safety': str,
    'max_signature_validity': str,
    'min_signature_validity': str,
    'max_validity_overlap': str,
    'min_validity_overlap': str,
    'ttl': All(int, Range(min=0)),
})

schema_slot_schema = Schema({
    'publish': Schema(Any(str, Schema([str]))),
    'sign': Schema(Any(str, Schema([str]))),
    'revoke': Schema(Any(str, Schema([str]))),
})

schema_schema = Schema({int: schema_slot_schema})

ksrsigner_config_schema = Schema({
    'hsm': Schema({str: hsm_schema}),
    'filenames': {
        'previous_skr': IsFile(),
        'input_ksr': IsFile(),
        'output_skr': IsFile(),
    },
    'keys': Schema({str: key_schema}),
    'request_policy': request_policy_schema,
    'response_policy': response_policy_schema,
    'ksk_policy': ksk_policy_schema,
    'schemas': Schema({str: schema_schema}),
})

wksr_config_schema = Schema({
    'tls': Schema({
        'cert': IsFile(),
        'key': IsFile(),
        'ca_cert': IsFile(),
        'ciphers': Schema([str]),
        'require_client_cert': bool,
        'client_whitelist': Schema([hexdigest]),
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
