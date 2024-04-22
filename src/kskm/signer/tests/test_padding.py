import unittest
from base64 import b64encode

from kskm.common.data import AlgorithmDNSSEC
from kskm.common.ecdsa_utils import ECCurve, KSKM_PublicKey_ECDSA
from kskm.common.rsa_utils import KSKM_PublicKey_RSA
from kskm.misc.hsm import KeyClass, KeyType, KSKM_P11Key, _format_data_for_signing, _p11

__author__ = "ft"


class Test_Sign_Formatting(unittest.TestCase):
    def setUp(self) -> None:
        self.rsa_key = KSKM_P11Key(
            label="RSA key",
            key_type=KeyType.RSA,
            key_class=KeyClass.PRIVATE,
            public_key=KSKM_PublicKey_RSA(
                bits=3, exponent=3, n=b"test"
            ),  # signatures get longer with larger keys
        )

        self.ecdsa_key = KSKM_P11Key(
            label="EC key",
            key_type=KeyType.EC,
            key_class=KeyClass.PRIVATE,
            public_key=KSKM_PublicKey_ECDSA(bits=256, q=b"test", curve=ECCurve.P256),
        )

    def test_raw_rsa_sha256(self) -> None:
        """Test formatting of raw RSA data for signing (SHA256)."""
        _data = b"test"
        _sign_data = _format_data_for_signing(
            self.rsa_key, _data, AlgorithmDNSSEC.RSASHA256
        )
        assert (
            b64encode(_sign_data.data)
            == b"AAEAMDEwDQYJYIZIAWUDBAIBBQAEIJ+G0IGITH1lmi/qoMVa0BWjv08bKwuCLNFdbBWw8AoI"
        )
        assert _sign_data.mechanism == _p11.CKM_RSA_X_509

    def test_raw_rsa_sha512(self) -> None:
        """Test formatting of raw RSA data for signing (SHA512)."""
        _data = b"test"
        _sign_data = _format_data_for_signing(
            self.rsa_key, _data, AlgorithmDNSSEC.RSASHA512
        )
        assert b64encode(_sign_data.data) == (
            b"AAEAMFEwDQYJYIZIAWUDBAIDBQAEQO4msN1K9+dJqhqO48EK6ZI/YYmAdy5HP4gZpdSUDg2yesGF"
            + b"+KDh1fhPiLyIf9Z7FDcywwTMX6mtjm9X9QAoqP8="
        )
        assert _sign_data.mechanism == _p11.CKM_RSA_X_509

    def test_raw_ecdsa_sha256(self) -> None:
        """Test formatting of raw ECDSA data for signing (SHA256)."""
        _data = b"test"
        _sign_data = _format_data_for_signing(
            self.ecdsa_key, _data, AlgorithmDNSSEC.ECDSAP256SHA256
        )
        assert b64encode(_sign_data.data) == (
            b"n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
        )
        assert _sign_data.mechanism == _p11.CKM_ECDSA

    def test_raw_ecdsa_sha384(self) -> None:
        """Test formatting of raw ECDSA data for signing (SHA384)."""
        _data = b"test"
        _sign_data = _format_data_for_signing(
            self.ecdsa_key, _data, AlgorithmDNSSEC.ECDSAP384SHA384
        )
        assert b64encode(_sign_data.data) == (
            b"doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp"
        )
        assert _sign_data.mechanism == _p11.CKM_ECDSA

    def test_rsa_hash_on_hsm(self) -> None:
        """Test formatting of data for signing after hashing on the HSM."""
        _data = b"test"
        _rsa_key = self.rsa_key.replace(hash_using_hsm=True)
        _sign_data = _format_data_for_signing(
            _rsa_key, _data, AlgorithmDNSSEC.RSASHA256
        )
        assert _sign_data.data == _data
        assert _sign_data.mechanism == _p11.CKM_SHA256_RSA_PKCS
