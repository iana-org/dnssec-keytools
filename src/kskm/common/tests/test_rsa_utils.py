import base64
import unittest

from kskm.common.rsa_utils import (
    KSKM_PublicKey_RSA,
    decode_rsa_public_key,
    encode_rsa_public_key,
)


class TestRsaUtils(unittest.TestCase):
    def test_encode_decode_rsa_public_key_short(self) -> None:
        """Test encode-decode with short exponent"""
        key = KSKM_PublicKey_RSA(bits=32, exponent=3, n=b"test")
        encoded = encode_rsa_public_key(key)
        decoded = decode_rsa_public_key(encoded)
        self.assertEqual(key, decoded)
        self.assertEqual(base64.b64decode(encoded), b"\x01\x03test")

    def test_encode_decode_rsa_public_key_long(self) -> None:
        """Test encode-decode with exponent requiring long length encoding"""
        key = KSKM_PublicKey_RSA(bits=32, exponent=16**2000, n=b"test")
        encoded = encode_rsa_public_key(key)
        decoded = decode_rsa_public_key(encoded)
        self.assertEqual(key, decoded)
        # verify long encoding was used
        self.assertEqual(base64.b64decode(encoded)[0:2], b"\x00\x03")

    def test_decode_rsa_public_key_two_bytes_exponent(self) -> None:
        """Test decode with exponent length encoded in two bytes"""
        expected = KSKM_PublicKey_RSA(bits=32, exponent=65537, n=b"test")
        decoded = decode_rsa_public_key(base64.b64encode(b"\x03\x01\x00\x01test"))
        self.assertEqual(expected, decoded)

    def test_encode_decode_rsa_public_key_four_bytes_exponent(self) -> None:
        """Test encode-decode with four bytes exponent"""
        key = KSKM_PublicKey_RSA(bits=32, exponent=0xAABBCCDD, n=b"test")
        encoded = encode_rsa_public_key(key)
        decoded = decode_rsa_public_key(encoded)
        self.assertEqual(key, decoded)
        self.assertEqual(base64.b64decode(encoded), b"\x04\xaa\xbb\xcc\xddtest")
