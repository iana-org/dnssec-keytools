"""Utility functions used in parsing SKRs."""

from kskm.common.parse_utils import keys_from_dict, parse_datetime, signature_from_dict
from kskm.skr.data import ResponseBundle

__author__ = "ft"


def responsebundles_from_list_of_dicts(bundles: list[dict]) -> list[ResponseBundle]:
    """Parse a list of KSR request bundle dicts."""
    return [
        ResponseBundle(
            id=bundle["attrs"]["id"],
            inception=parse_datetime(bundle["value"]["Inception"]),
            expiration=parse_datetime(bundle["value"]["Expiration"]),
            keys=keys_from_dict(bundle["value"]["Key"]),
            signatures=signature_from_dict(bundle["value"]["Signature"]),
        )
        for bundle in bundles
    ]
