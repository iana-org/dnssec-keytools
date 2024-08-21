import datetime
from base64 import b64decode, b64encode
from typing import Self

from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict

from kskm.common.config import KSKMConfig
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY, Key, Signer
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.signature import validate_signatures
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, DataToSign, KeyClass, KeyType, KSKM_P11Key
from kskm.signer import sign_bundles

__author__ = "ft"


class Mocked_EdDSA_Key(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    b64_private_key: str
    b64_public_key: str

    ed25519_private_key: ed25519.Ed25519PrivateKey
    ed25519_public_key: ed25519.Ed25519PublicKey

    @classmethod
    def from_private_key(cls, private_key: str) -> Self:
        _key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(private_key))
        _pub = _key.public_key()
        b64_pub = b64encode(_pub.public_bytes_raw()).decode()
        return cls(
            b64_private_key=private_key,
            b64_public_key=b64_pub,
            ed25519_private_key=_key,
            ed25519_public_key=_pub,
        )


class Mocked_KSKM_P11Key(KSKM_P11Key):
    eddsa_key: Mocked_EdDSA_Key

    def sign(self, data: DataToSign) -> bytes:
        """Sign some data using this key."""
        return self.eddsa_key.ed25519_private_key.sign(data.data)

    @classmethod
    def from_eddsa_key(
        cls, eddsa_key: Mocked_EdDSA_Key, label: str, key_class: KeyClass
    ) -> Self:
        return cls(
            label=label,
            key_type=KeyType.EC,
            key_class=key_class,
            eddsa_key=eddsa_key,
            public_key=b64decode(eddsa_key.b64_public_key),
        )


class Mocked_P11Module:
    # Example key from RFC 8080:
    #   Private-key-format: v1.2
    #   Algorithm: 15 (ED25519)
    #   PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
    #
    #   example.com. 3600 IN DNSKEY 257 3 15 (
    #                l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
    keys = {
        "ksk_EdDSA_1": Mocked_EdDSA_Key.from_private_key(
            "ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI="
        )
    }

    def find_key_by_label(
        self, label: str, key_class: KeyClass, hash_using_hsm: bool | None = None
    ) -> KSKM_P11Key | None:
        if label in self.keys:
            return Mocked_KSKM_P11Key.from_eddsa_key(self.keys[label], label, key_class)
        return None


def _get_test_config() -> KSKMConfig:
    return KSKMConfig.from_dict(
        {
            "schemas": {
                "test": {
                    1: {"publish": [], "sign": "ksk_EdDSA_1"},
                    2: {"publish": [], "sign": "ksk_EdDSA_1"},
                    3: {"publish": [], "sign": "ksk_EdDSA_1"},
                    4: {"publish": [], "sign": "ksk_EdDSA_1"},
                    5: {"publish": [], "sign": "ksk_EdDSA_1"},
                    6: {"publish": [], "sign": "ksk_EdDSA_1"},
                    7: {"publish": [], "sign": "ksk_EdDSA_1"},
                    8: {"publish": [], "sign": "ksk_EdDSA_1"},
                    9: {"publish": [], "sign": "ksk_EdDSA_1"},
                }
            },
            "ksk_policy": {
                "publish_safety": "P10D",
                "retire_safety": "P10D",
                "max_signature_validity": "P21D",
                "min_signature_validity": "P21D",
                "max_validity_overlap": "P16D",
                "min_validity_overlap": "P9D",
                "ttl": 20,
            },
            "keys": {
                "ksk_EdDSA_1": {
                    "description": "A mocked HSM key used in tests",
                    "label": "ksk_EdDSA_1",
                    "key_tag": 2008,
                    "algorithm": "ED25519",
                    "valid_from": datetime.datetime(
                        2010, 7, 15, 0, 0, tzinfo=datetime.timezone.utc
                    ),
                    "ds_sha256": "72C3E80B7AE481BF39BA87C505039124EA9C6B501AB2D26BC0489DBC4AF87250",
                }
            },
        }
    )


class SignWithMockedHSM_Baseclass:
    def setup_method(self) -> None:
        """Provide a baseline of things for each test."""
        self.config = _get_test_config()
        self.schema = self.config.get_schema("test")
        _policy = {
            "PublishSafety": "P10D",
            "RetireSafety": "P10D",
            "MaxSignatureValidity": "P20D",
            "MinSignatureValidity": "P15D",
            "MaxValidityOverlap": "P5D",
            "MinValidityOverlap": "P5D",
            "SignatureAlgorithm": {
                "attrs": {"algorithm": "15"},
                "value": {"EdDSA": {"attrs": {"size": "256"}, "value": ""}},
            },
        }
        self.request_zsk_policy = signature_policy_from_dict(_policy)

    def _make_request(
        self,
        zsk_keys: set[Key],
        inception: datetime.datetime | None = None,
        expiration: datetime.datetime | None = None,
        id_suffix: str = "",
        signers: set[Signer] | None = None,
        num_bundles: int = 1,
    ) -> Request:
        if inception is None:
            inception = parse_datetime("2024-01-01T00:00:00+00:00")
        if expiration is None:
            expiration = parse_datetime("2024-01-22T00:00:00+00:00")
        bundles: list[RequestBundle] = []
        for i in range(num_bundles):
            bundle = RequestBundle(
                id=f"test{id_suffix}_{i + 1}",
                inception=inception,
                expiration=expiration,
                keys=zsk_keys,
                signatures=set(),
                signers=signers,
            )
            bundles.append(bundle)
        request = Request(
            id="test-req-01" + id_suffix,
            serial=1,
            domain=".",
            bundles=bundles,
            zsk_policy=self.request_zsk_policy,
            timestamp=None,
        )
        return request


class Test_SignWithMocked_EdDSA(SignWithMockedHSM_Baseclass):
    def setup_method(self) -> None:
        super().setup_method()

        # Example key from RFC 8080:
        #   Private-key-format: v1.2
        #   Algorithm: 15 (ED25519)
        #   PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
        #
        #   example.com. 3600 IN DNSKEY 257 3 15 (
        #                l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
        zsk_key = public_key_to_dnssec_key(
            public_key=b64decode("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="),
            key_identifier="ksk_EdDSA_1",
            algorithm=AlgorithmDNSSEC.ED25519,
            flags=FlagsDNSKEY.ZONE.value,
            ttl=self.config.ksk_policy.ttl,
        )
        self.zsk_keys = {zsk_key}

    def test_sign_with_mocked_hsm(self) -> None:
        """Test signing a key record with a mocked HSM and then verifying it"""
        request = self._make_request(zsk_keys=self.zsk_keys)
        new_bundles = sign_bundles(
            request=request,
            schema=self.schema,
            p11modules=KSKM_P11([Mocked_P11Module()]),  # type: ignore
            config=self.config,
            ksk_policy=self.config.ksk_policy,
        )
        validate_signatures(list(new_bundles)[0])
