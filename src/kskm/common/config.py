"""Load and parse configuration."""
from __future__ import annotations

import logging
from dataclasses import replace
from typing import IO, Dict, Mapping, Optional, Type, cast

import voluptuous.error
import voluptuous.humanize
import yaml

from kskm.common.config_misc import (KSKKey, KSKKeysType, KSKPolicy,
                                     RequestPolicy, ResponsePolicy, Schema,
                                     SchemaAction, _parse_keylist)
from kskm.common.config_schema import KSRSIGNER_CONFIG_SCHEMA
from kskm.common.integrity import checksum_bytes2str

__author__ = 'ft'

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for errors in the configuration."""

    pass


class KSKMConfig(object):
    """
    Configuration object.

    Holds configuration loaded from ksrsigner.yaml.
    """

    def __init__(self, data: Mapping):
        """Initialise configuration from a Mapping."""
        self._data = dict(data)
        # lazily parsed parts of the configuration.
        self._hsm: Optional[Mapping] = None
        self._ksk_keys: Optional[KSKKeysType] = None
        self._ksk_policy: Optional[KSKPolicy] = None
        self._request_policy: Optional[RequestPolicy] = None
        self._response_policy: Optional[ResponsePolicy] = None

    @property
    def hsm(self) -> Mapping:
        """
        HSM configuration.

        Example:

            hsm:
              softhsm:
                module: /path/to/softhsm/libsofthsm2.so
                pin: 123456
                env:
                  SOFTHSM2_CONF: /path/to/softhsm.conf

        Returns a plain dict with the configuration for now.
        """
        if self._hsm is None:
            self._hsm = self._data.get('hsm', {})
        assert self._hsm is not None  # help type checker
        return self._hsm

    @property
    def ksk_policy(self) -> KSKPolicy:
        """
        Key Signing Key policy.

        Parameters from here are used when creating an SKR.

        Example:

            ksk_policy:
              publish_safety: PT0S
              retire_safety: P28D
              max_signature_validity: P21D
              min_signature_validity: P21D
              max_validity_overlap: P16D
              min_validity_overlap: P9D
              ttl: 172800
        """
        if self._ksk_policy is None:
            self._ksk_policy = KSKPolicy.from_dict(self._data.get('ksk_policy', {}))
        assert self._ksk_policy is not None  # help type checker
        return self._ksk_policy

    @property
    def ksk_keys(self) -> KSKKeysType:
        """
        Load KSK key definitions from the config.

        Example:
        ---
        keys:
          ksk_current:
            description: Root DNSSEC KSK 2010
            label: Kjqmt7v
            key_tag: 19036
            algorithm: RSASHA256
            rsa_size: 2048
            rsa_exponent: 65537
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
            ds_sha256: 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
        """
        if self._ksk_keys is None:
            res: Dict[str, KSKKey] = {}
            if 'keys' not in self._data:
                return cast(KSKKeysType, res)
            for name, v in self._data['keys'].items():
                key = KSKKey.from_dict(v)
                res[name] = key
            self._ksk_keys = cast(KSKKeysType, res)
        assert self._ksk_keys is not None  # help type checker
        return self._ksk_keys

    def get_filename(self, which: str) -> Optional[str]:
        """
        Get a filename from the configuration.

        Example:
            filenames:
              previous_skr: prev-skr.xml
              input_ksr: ksr.xml
              output_skr: skr.xml
              output_trustanchor: root-anchors.xml
        """
        if 'filenames' in self._data:
            _this = self._data['filenames'].get(which)
            if isinstance(_this, str):
                return _this
        return None

    @property
    def request_policy(self) -> RequestPolicy:
        """
        Policy for validating a request (KSR).

        Example:
            request_policy:
              acceptable_domains:
                - "."
              num_bundles: 9
              ...
        """
        if self._request_policy is None:
            policy = RequestPolicy.from_dict(self._data.get('request_policy', {}))
            if policy.dns_ttl == 0:
                # Replace with the value configured to be used when signing the bundles
                policy = replace(policy, dns_ttl=self.ksk_policy.ttl)
            self._request_policy = policy
        return self._request_policy

    @property
    def response_policy(self) -> ResponsePolicy:
        """
        Policy for validating a response (SKR).

        Since responses loaded have likely been created by the KSR signer itself,
        only some basic validation is performed.

        Example:
            response_policy:
              num_bundles: 9
              validate_signatures: True
        """
        if self._response_policy is None:
            self._response_policy = ResponsePolicy.from_dict(self._data.get('response_policy', {}))
        assert self._response_policy is not None  # help type checker
        return self._response_policy

    def get_schema(self, name: str) -> Schema:
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
        data = self._data['schemas'][name]
        _actions: Dict[int, SchemaAction] = {}
        for num in range(1, 10):
            _this = SchemaAction(publish=_parse_keylist(data[num]['publish']),
                                 sign=_parse_keylist(data[num]['sign']),
                                 revoke=_parse_keylist(data[num].get('revoke', [])))
            _actions[num] = _this
        return Schema(name=name, actions=_actions)

    def update(self, data: Mapping) -> None:
        """Update configuration on the fly. Usable in tests."""
        logger.warning(f'Updating configuration (sections {data.keys()})')
        self._data.update(data)

    def merge_update(self, data: Mapping) -> None:
        """Merge-update configuration on the fly. Usable in tests."""
        logger.warning(f'Merging configuration (sections {data.keys()})')
        for k, v in data.items():
            logger.debug(f'Updating config section {k} with {v}')
            self._data[k].update(v)
            logger.debug(f'Config now: {self._data[k]}')

    @classmethod
    def from_yaml(cls: Type[KSKMConfig], stream: IO) -> KSKMConfig:
        """Load configuration from a YAML stream."""
        config = yaml.safe_load(stream)
        try:
            voluptuous.humanize.validate_with_humanized_errors(config, KSRSIGNER_CONFIG_SCHEMA)
        except voluptuous.error.Error as exc:
            raise ConfigurationError(str(exc))
        return cls(config)


def get_config(filename: Optional[str]) -> KSKMConfig:
    """Top-level function to load configuration, or return a default ConfigType instance."""
    if not filename:
        # Avoid having Optional[ConfigType] everywhere by always having a config, even if it is empty
        logger.warning('No configuration filename provided, using default configuration.')
        return KSKMConfig({})
    with open(filename, 'rb') as fd:
        config_bytes = fd.read()
        logger.info("Loaded configuration from file %s %s", filename, checksum_bytes2str(config_bytes))
        fd.seek(0)
        return KSKMConfig.from_yaml(fd)
