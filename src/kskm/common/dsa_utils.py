"""Various functions relating to the DSA algorithm."""
from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyDSA

__author__ = 'ft'


def is_algorithm_dsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is the DSA algorithm."""
    return alg == AlgorithmDNSSEC.DSA


def parse_signature_policy_dsa(data: dict) -> AlgorithmPolicyDSA:
    """
    Parse DSA ZSK SignatureAlgorithm entries.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '3'},
     'value': {'DSA': {'attrs': {'size': '1024'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data['attrs']['algorithm']))
    attrs = data['value']['DSA']['attrs']
    dsa = AlgorithmPolicyDSA(bits=int(attrs['size']),
                             algorithm=attr_alg,
                             )
    return dsa
