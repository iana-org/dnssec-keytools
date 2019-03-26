"""Various functions relating to the DSA algorithm."""
from kskm.common.data import AlgorithmDNSSEC, AlgorithmPolicyDSA

__author__ = 'ft'


def is_algorithm_dsa(alg: AlgorithmDNSSEC) -> bool:
    """Check if `alg' is one of the known DSA algorithms."""
    # TODO: Are these the right ones? Have no examples of SignaturePolicy DSA.
    return alg in [AlgorithmDNSSEC.ECDSAP256SHA256,
                   AlgorithmDNSSEC.ECDSAP384SHA384,
                   ]


def parse_signature_policy_dsa(data: dict) -> AlgorithmPolicyDSA:
    """
    Parse DSA ZSK SignatureAlgorithm entrys.

    The ZSK policy on a parsed KSR XML contains dicts assumed to look like this:

    {'attrs': {'algorithm': '13'},
     'value': {'DSA': {'attrs': {'size': '1024'}, 'value': ''}}}
    """
    attr_alg = AlgorithmDNSSEC(int(data['attrs']['algorithm']))
    attrs = data['value']['DSA']['attrs']
    dsa = AlgorithmPolicyDSA(bits=int(attrs['size']),
                             algorithm=attr_alg,
                             )
    return dsa
