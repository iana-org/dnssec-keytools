"""Parse utilities common to both KSRs and SKRs."""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from kskm.common.data import (
    AlgorithmDNSSEC,
    AlgorithmPolicy,
    FlagsDNSKEY,
    Key,
    Signature,
    SignaturePolicy,
    Signer,
    TypeDNSSEC,
)
from kskm.common.ecdsa_utils import is_algorithm_ecdsa, parse_signature_policy_ecdsa
from kskm.common.eddsa_utils import is_algorithm_eddsa, parse_signature_policy_eddsa
from kskm.common.rsa_utils import is_algorithm_rsa, parse_signature_policy_rsa

__author__ = "ft"


logger = logging.getLogger(__name__)


#
# SignaturePolicy
#


def signature_policy_from_dict(policy: dict[str, Any]) -> SignaturePolicy:
    """Parse RequestBundle signature policy."""
    return SignaturePolicy(
        publish_safety=_get_timedelta(policy, "PublishSafety"),
        retire_safety=_get_timedelta(policy, "RetireSafety"),
        max_signature_validity=_get_timedelta(policy, "MaxSignatureValidity"),
        min_signature_validity=_get_timedelta(policy, "MinSignatureValidity"),
        max_validity_overlap=_get_timedelta(policy, "MaxValidityOverlap"),
        min_validity_overlap=_get_timedelta(policy, "MinValidityOverlap"),
        algorithms=_parse_signature_algorithms(policy["SignatureAlgorithm"]),
    )


def signers_from_list(signers: list[dict[str, Any]]) -> set[Signer] | None:
    """
    Parse RequestBundle signers.

    Example signers:
        [{'attrs': {'keyIdentifier': 'KC00020'}, 'value': ''},
         {'attrs': {'keyIdentifier': 'KC00094'}, 'value': ''},
        ]
    """
    if not signers:
        return None
    return {Signer(key_identifier=this["attrs"]["keyIdentifier"]) for this in signers}


def _parse_signature_algorithms(
    algorithms: dict[str, Any] | list[dict[str, Any]],
) -> set[AlgorithmPolicy]:
    """
    Parse data such as:

        [{'attrs': {'algorithm': '8'}, 'value': {'RSA': {...}}}, {...}]

    into a set of AlgorithmPolicy instances.
    """
    _algs = algorithms if isinstance(algorithms, list) else [algorithms]
    res: set[AlgorithmPolicy] = set()
    for this in _algs:
        attr_alg = AlgorithmDNSSEC(int(this["attrs"]["algorithm"]))
        if is_algorithm_rsa(attr_alg):
            res.add(parse_signature_policy_rsa(this))
        elif is_algorithm_ecdsa(attr_alg):
            res.add(parse_signature_policy_ecdsa(this))
        elif is_algorithm_eddsa(attr_alg):
            res.add(parse_signature_policy_eddsa(this))
        else:
            raise NotImplementedError(
                f"Unhandled SignaturePolicy algorithm: {attr_alg}"
            )
    return res


def _get_timedelta(policy: dict[str, Any], name: str) -> timedelta:
    """Extract a timedelta from the policy."""
    return duration_to_timedelta(policy[name])


def duration_to_timedelta(duration: str | None) -> timedelta:
    """Parse strings such as P14D or PT1H5M (ISO8601 durations) into time deltas."""
    if not duration:
        return timedelta()
    if not duration.startswith("P"):
        raise ValueError(f'Duration does not start with "P": {duration}')
    duration = duration[1:]
    res = timedelta()
    _re = re.compile(r"^(\d+?)([WDHMS])(.*)")
    # 'M' means month until we see a 'T', then it means minutes
    time_section = False
    while duration:
        if duration.startswith("T"):
            time_section = True
            duration = duration[1:]
        m = _re.match(duration)
        if not m:
            raise ValueError(f"Invalid ISO8601 duration (at {duration})")
        num_str, what, rest = m.groups()
        num = int(num_str)
        if what == "W":
            res += timedelta(days=7 * num)
        elif what == "D":
            res += timedelta(days=num)
        elif what == "H":
            res += timedelta(hours=num)
        elif what == "M":
            if time_section:
                res += timedelta(minutes=num)
            else:
                # the length of one month is different depending on start date,
                # we don't have that concept here so disallow it for now
                raise NotImplementedError("Months are not supported")
        elif what == "S" or what == "":
            res += timedelta(seconds=num)
        try:
            res += timedelta(seconds=int(rest))
            rest = ""
        except ValueError:
            pass
        duration = rest
    return res


def parse_datetime(date: str) -> datetime:
    """
    Parse a UTC timestamp.

    If the timestamp is _not_ in UTC, this function will reject it.
    If the timestamp contains no timezone, UTC is assumed.
    """
    while date.endswith("Z"):
        date = date[:-1]
    dt = datetime.fromisoformat(date)
    if dt.tzinfo and dt.tzinfo is not timezone.utc:
        raise ValueError(f"Timestamps MUST be UTC (not {dt.tzinfo} as in {date})")
    return dt.replace(tzinfo=timezone.utc)


KeyAsDict = dict[str, dict[str, str]]


def keys_from_dict(
    keys: KeyAsDict | list[KeyAsDict],
) -> set[Key]:
    """
    Parse Bundle keys.

    Example keys:
        [{'attrs': {'keyIdentifier': 'ZSK-24315', 'keyTag': '24315'},
          'value': {'Algorithm': '5',
                    'Flags': '256',
                    'Protocol': '3',
                    'PublicKey': 'A...'}}
         ]
    """
    if not isinstance(keys, list):
        keys = [keys]
    return _keys_from_list(keys)


def _keys_from_list(keys: list[KeyAsDict]) -> set[Key]:
    return {
        Key(
            key_identifier=key["attrs"]["keyIdentifier"],
            key_tag=int(key["attrs"]["keyTag"]),
            ttl=int(key["value"]["TTL"]),
            flags=int(key["value"]["Flags"]),
            protocol=int(key["value"]["Protocol"]),
            algorithm=AlgorithmDNSSEC(int(key["value"]["Algorithm"])),
            public_key=bytes(key["value"]["PublicKey"], "utf-8"),
        )
        for key in keys
    }


def signature_from_dict(signatures: dict[str, Any]) -> set[Signature]:
    """
    Parse Bundle signature.

    Example sig:
        {'attrs': {'keyIdentifier': 'ZSK-24315'},
         'value': {'Algorithm': '5',
                   'KeyTag': '24315',
                   'Labels': '0',
                   'OriginalTTL': '3600',
                   'Signature': 'SIG...',
                   'SignatureExpiration': '2009-09-24T18:22:41Z',
                   'SignatureInception': '2009-08-25T18:22:41Z',
                   'SignersName': '.',
                   'TypeCovered': '48'
                   }
        }
    """
    if not isinstance(signatures, list):
        return _signature_from_list([signatures])
    return _signature_from_list(signatures)


def _signature_from_list(signatures: list[dict[str, Any]]) -> set[Signature]:
    return {
        Signature(
            key_identifier=sig["attrs"].get("keyIdentifier"),
            ttl=int(sig["value"]["TTL"]),
            type_covered=TypeDNSSEC[sig["value"]["TypeCovered"]],
            algorithm=AlgorithmDNSSEC(int(sig["value"]["Algorithm"])),
            labels=int(sig["value"]["Labels"]),
            original_ttl=int(sig["value"]["OriginalTTL"]),
            signature_expiration=parse_datetime(sig["value"]["SignatureExpiration"]),
            signature_inception=parse_datetime(sig["value"]["SignatureInception"]),
            key_tag=int(sig["value"]["KeyTag"]),
            signers_name=sig["value"]["SignersName"],
            signature_data=bytes(sig["value"]["SignatureData"], "utf-8"),
        )
        for sig in signatures
    }


def is_sep_key(key: Key) -> bool:
    """
    Return True if the key has the SEP (secure entry point) bit set.

    Keys with the SEP flag set are KSKs, and keys without it are ZSKs.
    """
    return bool(key.flags & FlagsDNSKEY.SEP.value)


def is_zsk_key(key: Key) -> bool:
    """Return True if the key is a zone signing key (does not have SEP flag set)."""
    return not is_sep_key(key)


def is_revoked_key(key: Key) -> bool:
    """Return True if the key has the SEP (secure entry point) bit set."""
    return bool(key.flags & FlagsDNSKEY.REVOKE.value)
