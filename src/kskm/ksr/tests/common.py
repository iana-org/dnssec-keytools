import unittest
from dataclasses import replace
from typing import Optional

from kskm.common.config_misc import RequestPolicy
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY
from kskm.common.parse_utils import duration_to_timedelta


class Test_Requests(unittest.TestCase):
    def setUp(self) -> None:
        # a policy that works with the default _make_request
        self.policy = RequestPolicy(
            num_bundles=1,
            check_cycle_length=False,
            check_keys_match_ksk_operator_policy=False,
            rsa_approved_exponents=[3, 65537],
            rsa_approved_key_sizes=[1024],
            signature_validity_match_zsk_policy=False,
            signature_check_expire_horizon=False,
            approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
        )

    def _make_request(
        self,
        domain: str = ".",
        request_policy: Optional[str] = None,
        request_bundle: Optional[str] = None,
    ):
        if request_policy is None:
            request_policy = self._make_request_policy()
        if request_bundle is None:
            request_bundle = self._make_request_bundle()
        xml = f"""
    <KSR domain="{domain}" id="test" serial="0">
      <Request>
        {request_policy}

        {request_bundle}
      </Request>
    </KSR>
    """
        return xml.strip()

    def _make_request_policy(self, signature_algorithm: Optional[str] = None) -> str:
        if signature_algorithm is None:
            signature_algorithm = self._make_signature_algorithm()
        xml = f"""
        <RequestPolicy>
          <ZSK>
            <PublishSafety>P10D</PublishSafety>
            <RetireSafety>P10D</RetireSafety>
            <MaxSignatureValidity>P21D</MaxSignatureValidity>
            <MinSignatureValidity>P21D</MinSignatureValidity>
            <MaxValidityOverlap>P12D</MaxValidityOverlap>
            <MinValidityOverlap>P9D</MinValidityOverlap>
            {signature_algorithm}
          </ZSK>
        </RequestPolicy>
        """
        return xml.strip()

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="8">
              <RSA size="1024" exponent="65537"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _make_request_bundle(
        self,
        bundle_id: str = "test-id",
        bundle_inception: str = "2009-11-03T00:00:00",
        bundle_expiration: str = "2009-11-17T23:59:59",
        key_identifier: str = "testkey",
        key_tag: int = 49920,
        flags: int = FlagsDNSKEY.ZONE.value,
        algorithm: int = AlgorithmDNSSEC.RSASHA256.value,
        pubkey: Optional[str] = None,
        signature_inception: str = "2009-11-09T20:33:05",
        signature_expiration: str = "2009-12-09T20:33:05",
        signature: Optional[str] = None,
    ) -> str:
        if pubkey is None:
            pubkey = (
                "AwEAAc2UsIt5d8lxdDil/4pLZVG8Y+kYc1Jf3RRAUzK1/ntFXcWL8gEDmuw6vBW8SiRF+HLKXTmEvqjE4SVV2HouhUb0SxR"
                "ts5/q59g++K9F1XsnDeMavXAA2R4Pca7VepNq7jisMEPpWc5U7FWeSdsFZtHus1oRQ4QdBLU1dZIaehsl"
            )
        if signature is None:
            signature = (
                "ja4WnG5U5yPn2+1mUcfVNhUddqutmsqlhSQzMVtGbxP5RaoOqHWkU/I4fmFUC9Uov4WZ4KAi5Fy7KcexC57pBPsgQe4g"
                "i3ghyrcnQzLt4HPxNTLCPyQvbzHp+h2dXLvgLaGiMcWYzWn9aYE0RGQgMRSWd3NKmKsO/NnlKV41tSo="
            )
        xml = f"""
        <RequestBundle id="{bundle_id}">
          <Inception>{bundle_inception}</Inception>
          <Expiration>{bundle_expiration}</Expiration>
          <Key keyIdentifier="{key_identifier}" keyTag="{key_tag}">
            <TTL>172800</TTL>
            <Flags>{flags}</Flags>
            <Protocol>3</Protocol>
            <Algorithm>{algorithm}</Algorithm>
            <PublicKey>{pubkey}</PublicKey>
          </Key>
          <Signature keyIdentifier="{key_identifier}">
            <TTL>172800</TTL>
            <TypeCovered>DNSKEY</TypeCovered>
            <Algorithm>{algorithm}</Algorithm>
            <Labels>0</Labels>
            <OriginalTTL>172800</OriginalTTL>
            <SignatureInception>{signature_inception}</SignatureInception>
            <SignatureExpiration>{signature_expiration}</SignatureExpiration>
            <KeyTag>{key_tag}</KeyTag>
            <SignersName>.</SignersName>
            <SignatureData>{signature}</SignatureData>
          </Signature>
        </RequestBundle>
        """
        return xml.strip()


class Test_Requests_With_Two_Bundles(Test_Requests):
    def setUp(self):
        super().setUp()
        # the public part of key RSA1 in softhsm
        self.RSA1 = """
        AwEAAcBH41eazGJG/DBdDmKxGxO8Bv4XbgNQiButvR60Aqzprd6DMT2J0xtR91MkkGYKj9Gc0nO9nBQFC4/zPEAlqE1HWnx4E57o
        BHSpij/B5MJYHIW1khGrjuRYooy8/q8C3U/PktxTxc6UlUqmPGL/dk5WYUOQsP8zayx/QSgc7wCR17CUvoaVyM05SPQyW20ztKEu
        oLkbWRG0vIDH84txq9oCBg4feuWVNl7VIIh3Sd7wRksMn2G8yz7zCs9btOP7SOcNlsGyw5f4syQmgQU5/UCt0FVF6w2LgT9pqR9r
        /+3kiO25oUc8+wZnA+ZhYVESoKCMb6G7UHty+6CTvQOxh8M=
        """

        # a policy that works with the default _make_request
        self.policy = RequestPolicy(
            num_bundles=2,
            num_keys_per_bundle=[1, 1],
            num_different_keys_in_all_bundles=1,
            rsa_approved_key_sizes=[2048],
            approved_algorithms=[AlgorithmDNSSEC.RSASHA256.name],
            validate_signatures=False,  # signatures are tested elsewhere
            signature_horizon_days=-1,  # allow signatures in the past
            min_cycle_inception_length=duration_to_timedelta("P11D"),
        )

    def _make_request(
        self,
        domain: str = ".",
        request_policy: Optional[str] = None,
        bundle1: Optional[str] = None,
        bundle2: Optional[str] = None,
    ):
        signature = """
        qeD7321YJ0g2ihT8XHPGIkMVumQoL7tdTQ6fMttyxmLeCMSE3K2cQBBQd622FGuF88JRiZKrQxWMfx2aow5k0WehytAhqaXy
        7DVzNJ+vxa0N5JoczkTMdNp6zF/L5DF2xbxgY88Yu9WVXZ0vpn5rx8bHwgsvrTfGhYWHipMgHBZpgmpWR2sS60mW/FnljmQE
        oiTk8np6QRGEVXZXX1QA7D/x+ey25aQfJxMuBT9ajTnUiGhUQz4GN6Eg5lgN6Ys3Yrqh7UuaDZjGTmrpNbbuym9VY0zTh7fj
        4avLezCphA7ZR2L8V1zkTdekC9qa+AGNFpK6BwnWLnI0ZWF9JqUs/Q==
        """.strip()
        if request_policy is None:
            request_policy = self._make_request_policy()
        if bundle1 is None:
            bundle1 = self._make_request_bundle(
                bundle_id="test-1",
                bundle_inception="2019-01-01T00:00:00",
                bundle_expiration="2019-01-22T00:00:00",
                key_identifier="RSA1",
                key_tag=25485,
                pubkey=self.RSA1,
                signature_inception="2019-01-01T00:00:00",
                signature_expiration="2019-01-22T00:00:00",
                signature=signature,
            )
        if bundle2 is None:
            bundle2 = self._make_request_bundle(
                bundle_id="test-2",
                bundle_inception="2019-01-12T00:00:00",
                bundle_expiration="2019-02-02T00:00:00",
                key_identifier="RSA1",
                key_tag=25485,
                pubkey=self.RSA1,
                signature_inception="2019-01-12T00:00:00",
                signature_expiration="2019-02-02T00:00:00",
                signature=signature,
            )
        xml = f"""
    <KSR domain="{domain}" id="test" serial="0">
      <Request>
        {request_policy}

        {bundle1}

        {bundle2}
      </Request>
    </KSR>
    """
        return xml.strip()

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.RSASHA256.value}">
              <RSA size="2048" exponent="65537"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _get_two_bundles(
        self,
        bundle1_inception="2019-01-01T00:00:00",
        bundle1_expiration="2019-01-22T00:00:00",
        bundle2_inception="2019-02-01T00:00:00",
        bundle2_expiration="2019-02-22T00:00:00",
    ):
        bundle1 = self._make_request_bundle(
            bundle_id="test-1",
            bundle_inception=bundle1_inception,
            bundle_expiration=bundle1_expiration,
            key_identifier="RSA1",
            key_tag=25485,
            pubkey=self.RSA1,
            # Like TTL, signature inception/expiration are arbitrary
            signature_inception="2009-12-21T22:24:01",
            signature_expiration="2009-12-21T22:25:05",
        )
        bundle2 = self._make_request_bundle(
            bundle_id="test-2",
            bundle_inception=bundle2_inception,
            bundle_expiration=bundle2_expiration,
            key_identifier="RSA1",
            key_tag=25485,
            pubkey=self.RSA1,
            # Like TTL, signature inception/expiration are arbitrary
            signature_inception="2009-12-21T22:24:01",
            signature_expiration="2009-12-21T22:25:05",
        )
        return bundle1, bundle2


class Test_Validate_KSR_ECDSA(Test_Requests):
    def setUp(self):
        super().setUp()
        self.policy = replace(
            self.policy,
            enable_unsupported_ecdsa=True,
            approved_algorithms=[AlgorithmDNSSEC.ECDSAP256SHA256.name],
        )

    def _make_signature_algorithm(self) -> str:
        xml = f"""
            <SignatureAlgorithm algorithm="{AlgorithmDNSSEC.ECDSAP256SHA256.value}">
              <ECDSA size="256"/>
            </SignatureAlgorithm>
        """
        return xml.strip()

    def _make_request_bundle(
        self,
        bundle_id: str = "test-id",
        bundle_inception: str = "2009-11-01T00:00:00",
        bundle_expiration: str = "2009-11-22T00:00:00",
        key_identifier: str = "EC1",
        key_tag: int = 45612,
        flags: int = FlagsDNSKEY.ZONE.value,
        algorithm: int = AlgorithmDNSSEC.ECDSAP256SHA256.value,
        pubkey: Optional[str] = None,
        signature_inception: str = "2009-11-09T20:33:05",
        signature_expiration: str = "2009-12-09T20:33:05",
        signature: Optional[str] = None,
    ) -> str:
        if pubkey is None:
            # Key EC1 in SoftHSM
            pubkey = "BGuqYyOGr0p/uKXm0MmP4Cuiml/a8FCPRDLerVyBS4jHmJlKTJmYk/nCbOp936DSh5SMu6+2WYJUI6K5AYfXbTE="
        if signature is None:
            # Signature generated manually using RRSIG data from the request below, and signed with SoftHSM
            signature = "m3sDohyHv+OKUs3KUbCpNeLf5F4m0fy3v92T9XAOeZJ08fOnylYx+lpzkkAV5ZLVzR/rL2d4eIVbRizWumfHFQ=="
        return super()._make_request_bundle(
            bundle_id=bundle_id,
            bundle_inception=bundle_inception,
            bundle_expiration=bundle_expiration,
            key_identifier=key_identifier,
            key_tag=key_tag,
            flags=flags,
            algorithm=algorithm,
            pubkey=pubkey,
            signature_inception=signature_inception,
            signature_expiration=signature_expiration,
            signature=signature,
        )
