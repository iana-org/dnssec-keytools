"""Load and parse configuration."""
from __future__ import annotations

import logging
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (IO, Dict, Iterable, List, Mapping, NewType, Optional, Type,
                    Union)

import yaml

from kskm.common.data import AlgorithmDNSSEC, SignaturePolicy
from kskm.common.integrity import checksum_bytes2str
from kskm.common.parse_utils import duration_to_timedelta, parse_datetime

__author__ = 'ft'
logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for errors in the configuration."""

    pass


ConfigType = NewType('ConfigType', Mapping)


def get_config(filename: Optional[str]) -> ConfigType:
    """Top-level function to load configuration, or return a default ConfigType instance."""
    if not filename:
        # Avoid having Optional[ConfigType] everywhere by always having a config, even if it is empty
        return ConfigType({})
    with open(filename, 'rb') as fd:
        config_bytes = fd.read()
        logger.info("Loaded configuration from file %s %s", filename, checksum_bytes2str(config_bytes))
        fd.seek(0)
        return load_from_yaml(fd)


def load_from_yaml(stream: IO) -> ConfigType:
    """Load configuration from a YAML stream."""
    return ConfigType(yaml.safe_load(stream))


def filename(which: str, config: ConfigType) -> Optional[str]:
    """Get a filename from the configuration."""
    if config and 'filenames' in config:
        _this = config['filenames'].get(which)
        if isinstance(_this, str):
            return _this
    return None


SigningKey = NewType('SigningKey', str)


@dataclass(frozen=True)
class SchemaAction(object):
    """Actions to take for a specific bundle."""

    publish: Iterable[SigningKey]
    sign: Iterable[SigningKey]
    revoke: Iterable[SigningKey]


@dataclass(frozen=True)
class Schema(object):
    """A named schema used when signing KSRs."""

    name: str
    actions: Mapping[int, SchemaAction]


def get_schema(name: str, config: ConfigType) -> Schema:
    """
    Parse a named entry from the 'schemas' section of config.

    Example config:

        schemas:
          revoke:
        1:
          publish:
            - ksk_current
            - ksk_next
          sign: ksk_next
        2:
          publish: ksk_next
          revoke: ksk_current
          sign:
            - ksk_current
            - ksk_next
        ...
        9:
          publish: ksk_next
          sign: ksk_next

    Note that 'revoke' is optional. Entries may be single key names, or
    list of key names. In the resulting Schema, it is always a list of key names,
    even if there is a single key name in the list.

    :return: A Schema instance for the schema requested.
    """
    data = config['schemas'][name]
    _actions: Dict[int, SchemaAction] = {}
    for num in range(1, 9):
        _this = SchemaAction(publish=_parse_keylist(data[num]['publish']),
                             sign=_parse_keylist(data[num]['sign']),
                             revoke=_parse_keylist(data[num].get('revoke', [])))
        _actions[num] = _this
    return Schema(name=name, actions=_actions)


def _parse_keylist(elem: Union[str, List[str]]) -> List[SigningKey]:
    if isinstance(elem, list):
        return [SigningKey(x) for x in elem]
    return [SigningKey(elem)]


@dataclass()
class KSKPolicy(object):
    """
    Signing policy for the KSK operator.

    This corresponds to the 'ksk_policy' section of ksrsigner.yaml.
    """

    signature_policy: SignaturePolicy
    ttl: int
    signers_name: str = '.'


def get_ksk_policy(config: ConfigType) -> KSKPolicy:
    """
    Load the 'ksk_policy' section of the configuration.

    Algorithms are not initialised here, but rather created dynamically from the KSK keys used
    in the schema.
    """
    _sp = SignaturePolicy(publish_safety=_ksk_policy_timedelta(config, 'publish_safety'),
                          retire_safety=_ksk_policy_timedelta(config, 'retire_safety'),
                          max_signature_validity=_ksk_policy_timedelta(config, 'max_signature_validity'),
                          min_signature_validity=_ksk_policy_timedelta(config, 'min_signature_validity'),
                          max_validity_overlap=_ksk_policy_timedelta(config, 'max_validity_overlap'),
                          min_validity_overlap=_ksk_policy_timedelta(config, 'min_validity_overlap'),
                          algorithms=set(),
                          )
    return KSKPolicy(signature_policy=_sp,
                     ttl=int(config['ksk_policy'].get('ttl', 172800)),
                     )


def _ksk_policy_timedelta(config: ConfigType, name: str) -> timedelta:
    return duration_to_timedelta(config['ksk_policy'][name])


@dataclass()
class KSKKey(object):
    """
    A key that can be used in schemas.

    This corresponds to an entry in the 'keys' section of ksrsigner.yaml.
    """

    description: str
    label: str
    algorithm: AlgorithmDNSSEC
    valid_from: datetime
    valid_until: Optional[datetime] = None
    rsa_size: Optional[int] = None
    rsa_exponent: Optional[int] = None

    @classmethod
    def from_dict(cls: Type[KSKKey], data: dict) -> KSKKey:
        """Instantiate KSKKey from a dict of values."""
        # do not modify callers data
        _data = deepcopy(data)
        if 'algorithm' in _data:
            _data['algorithm'] = AlgorithmDNSSEC[_data['algorithm']]
        for _dt in ['valid_from', 'valid_until']:
            # If the dict is loaded from YAML, these values will already be converted to datetime.
            # If they are not, convert them here.
            if _dt in _data and not isinstance(_data[_dt], datetime):
                _data[_dt] = parse_datetime(_data[_dt])
            elif _dt in _data:
                # Set timezone UTC in the datetime
                _data[_dt] = _data[_dt].replace(tzinfo=timezone.utc)
        return cls(**_data)


KSKKeysType = NewType('KSKKeysType', Mapping[str, KSKKey])


def get_ksk_keys(config: ConfigType) -> KSKKeysType:
    """
    Load KSK key definitions from the config.

    Example:
    ---
    keys:
      ksk_current:
        description: Root DNSSEC KSK 2010
        label: Kjqmt7v
        algorithm: RSASHA256
        rsa_size: 2048
        rsa_exponent: 65537
        valid_from: 2010-07-15T00:00:00+00:00
        valid_until: 2019-01-11T00:00:00+00:00
    """
    res: Dict[str, KSKKey] = {}
    if 'keys' not in config:
        return KSKKeysType(res)
    for name, v in config['keys'].items():
        key = KSKKey.from_dict(v)
        res[name] = key
    return KSKKeysType(res)
