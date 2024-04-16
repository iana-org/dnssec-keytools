"""Load and parse configuration."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import replace
from io import BufferedReader, StringIO
from typing import Any

import voluptuous.error
import voluptuous.humanize
import yaml
from pydantic import BaseModel, ConfigDict, Field

from kskm.common.config_misc import (
    KSKKey,
    KSKPolicy,
    RequestPolicy,
    ResponsePolicy,
    Schema,
    SchemaAction,
    parse_keylist,
)
from kskm.common.config_schema import KSRSIGNER_CONFIG_SCHEMA
from kskm.common.integrity import checksum_bytes2str

__author__ = "ft"

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for errors in the configuration."""


class KSKMConfig(BaseModel):
    """
    Configuration object.

    Holds configuration loaded from ksrsigner.yaml.
    """

    # TODO: model_config = ConfigDict(extra="forbid")

    data_: dict[str, Any]
    """
    HSM configuration.

    Returns a plain dict with the configuration for now.

    Example:
    -------
        hsm:
            softhsm:
            module: /path/to/softhsm/libsofthsm2.so
            pin: 123456
            env:
                SOFTHSM2_CONF: /path/to/softhsm.conf

    """
    hsm: Mapping[str, Any] | None = None

    """
    Load KSK key definitions from the config.

    Example:
    -------
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
    ksk_keys: Mapping[str, KSKKey] = Field(default_factory=dict, alias="keys")

    """
    Key Signing Key policy.

    Parameters from here are used when creating an SKR.

    Example:
    -------
        ksk_policy:
            publish_safety: PT0S
            retire_safety: P28D
            max_signature_validity: P21D
            min_signature_validity: P21D
            max_validity_overlap: P16D
            min_validity_overlap: P9D
            ttl: 172800

    """
    ksk_policy: KSKPolicy = KSKPolicy()
    request_policy: RequestPolicy = RequestPolicy()
    response_policy: ResponsePolicy = ResponsePolicy()

    def get_filename(self, which: str) -> str | None:
        """
        Get a filename from the configuration.

        Example:
        -------
            filenames:
              previous_skr: prev-skr.xml
              input_ksr: ksr.xml
              output_skr: skr.xml
              output_trustanchor: root-anchors.xml

        """
        if "filenames" in self.data_:
            _this = self.data_["filenames"].get(which)
            if isinstance(_this, str):
                return _this
        return None

    @property
    def get_request_policy(self) -> RequestPolicy:
        """
        Policy for validating a request (KSR).

        Example:
        -------
            request_policy:
              acceptable_domains:
                - "."
              num_bundles: 9
              ...

        """
        # TODO: Implement this when parsing the policy instead of when using it
        if self.request_policy.dns_ttl == 0:
            # Replace with the value configured to be used when signing the bundles
            _data = self.request_policy.model_dump()
            _data["dns_ttl"] = self.ksk_policy.ttl
            return RequestPolicy(**_data)
        return self.request_policy

    def get_schema(self, name: str) -> Schema:
        """
        Parse a named entry from the 'schemas' section of config.

        Example:
        -------
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
        data = self.data_["schemas"][name]
        _actions: dict[int, SchemaAction] = {}
        for num in range(1, self.get_request_policy.num_bundles + 1):
            _this = SchemaAction(
                publish=parse_keylist(data[num]["publish"]),
                sign=parse_keylist(data[num]["sign"]),
                revoke=parse_keylist(data[num].get("revoke", [])),
            )
            _actions[num] = _this
        return Schema(name=name, actions=_actions)

    def update(self, data: Mapping[str, Any]) -> None:
        """Update configuration on the fly. Usable in tests."""
        logger.warning(f"Updating configuration (sections {data.keys()})")
        self.data_.update(data)
        self._update_parts()

    def _update_parts(self) -> None:
        new_config = KSKMConfig.from_dict(self.data_)
        self.hsm = new_config.hsm
        self.ksk_keys = new_config.ksk_keys
        self.ksk_policy = new_config.ksk_policy

    def merge_update(self, data: Mapping[str, Any]) -> None:
        """Merge-update configuration on the fly. Usable in tests."""
        logger.warning(f"Merging configuration (sections {data.keys()})")
        for k, v in data.items():
            logger.debug(f"Updating config section {k} with {v}")
            self.data_[k].update(v)
            logger.debug(f"Config now: {self.data_[k]}")
        self._update_parts()

    @classmethod
    def from_yaml(
        cls: type[KSKMConfig], stream: BufferedReader | StringIO
    ) -> KSKMConfig:
        """Load configuration from a YAML stream."""
        config = yaml.safe_load(stream)
        try:
            voluptuous.humanize.validate_with_humanized_errors(
                config, KSRSIGNER_CONFIG_SCHEMA
            )
            logger.info("Configuration validated")
        except voluptuous.error.Error as exc:
            raise ConfigurationError(str(exc)) from exc
        return KSKMConfig.from_dict(config)

    @classmethod
    def from_dict(cls: type[KSKMConfig], config: dict[str, Any]) -> KSKMConfig:
        if "ksk_policy" in config:
            # put everything except ttl and signers_name into signature_policy
            _signature_policy = config.get("ksk_policy", {})
            _new_ksk_policy = {"signature_policy": _signature_policy}
            for _move in ["ttl", "signers_name"]:
                if _move in _signature_policy:
                    _new_ksk_policy[_move] = _signature_policy.pop(_move)
            config["ksk_policy"] = _new_ksk_policy

        return cls(**config, data_=config)


def get_config(filename: str | None) -> KSKMConfig:
    """Top-level function to load configuration, or return a default ConfigType instance."""
    if not filename:
        # Avoid having Optional[ConfigType] everywhere by always having a config, even if it is empty
        logger.warning(
            "No configuration filename provided, using default configuration."
        )
        return KSKMConfig(data_={})
    with open(filename, "rb") as fd:
        config_bytes = fd.read()
        logger.info(
            "Loaded configuration from file %s %s",
            filename,
            checksum_bytes2str(config_bytes),
        )
        fd.seek(0)
        return KSKMConfig.from_yaml(fd)
