"""
Utility functions to parse elements of KSRs.

The KSR XML files are parsed using the minimal parser in kskm.common.xml_parser,
which returns a nested dict with all the data. The functions in this
module know how to interpret parts of that dict and turn it into the
dataclasses from kskm.ksr.data.
"""
import logging
from typing import List

from kskm.common.parse_utils import (
    keys_from_dict,
    parse_datetime,
    signature_from_dict,
    signers_from_list,
)
from kskm.ksr.data import RequestBundle

__author__ = "ft"


logger = logging.getLogger(__name__)


def requestbundles_from_list_of_dicts(bundles: list[dict]) -> list[RequestBundle]:
    """
    Parse a list of KSR request bundle dicts.

    Example bundles:
        [{'attrs': {'id': '46E2E616-91A4-11DE-AC37-E3B2CDA0AB07'},
          'value': {'Expiration': '2009-09-01T20:22:41Z',
                    'Inception': '2009-08-25T20:22:41Z',
                    'Key': {'attrs': {'keyIdentifier': 'ZSK-24315', 'keyTag': '24315'},
                            'value': {'Algorithm': '5',
                                      'Flags': '256',
                                      'Protocol': '3',
                                      'PublicKey': 'A...'}},
                    'Signature': {'attrs': {'keyIdentifier': 'ZSK-24315'},
                                  'value': {'Algorithm': '5',
                                            'KeyTag': '24315',
                                            'Labels': '0',
                                            'OriginalTTL': '3600',
                                            'Signature': 'SIG...',
                                            'SignatureExpiration': '2009-09-24T18:22:41Z',
                                            'SignatureInception': '2009-08-25T18:22:41Z',
                                            'SignersName': '.',
                                            'TypeCovered': '48'}},
                    'Signer': [{'attrs': {'keyIdentifier': 'KC00020'}, 'value': ''},
                               {'attrs': {'keyIdentifier': 'KC00094'}, 'value': ''},
                               ]
                    },
          }]
    """
    res = []
    for bundle in bundles:
        id = bundle["attrs"].get("id")
        if not id:
            raise ValueError("Bundle missing ID")
        for name in ["Inception", "Expiration", "Key", "Signature"]:
            if name not in bundle["value"]:
                raise ValueError(f"Bundle {id} missing mandatory {name}")
        this = RequestBundle(
            id=bundle["attrs"]["id"],
            inception=parse_datetime(bundle["value"]["Inception"]),
            expiration=parse_datetime(bundle["value"]["Expiration"]),
            keys=keys_from_dict(bundle["value"]["Key"]),
            signatures=signature_from_dict(bundle["value"]["Signature"]),
            signers=signers_from_list(bundle["value"].get("Signer", [])),
        )
        res += [this]
    # Sort bundles after expiration time
    return sorted(res, key=lambda x: x.expiration)
