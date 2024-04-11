import datetime
from unittest import TestCase

from kskm.common.data import AlgorithmDNSSEC, Key, Signature, Signer, TypeDNSSEC
from kskm.common.parse_utils import (
    duration_to_timedelta,
    keys_from_dict,
    signature_from_dict,
)
from kskm.ksr.parse_utils import signers_from_list


class Test_duration_to_timedelta(TestCase):
    def test_duration_to_timedelta_empty(self):
        """Test empty input"""
        td = duration_to_timedelta("")
        self.assertEqual(td.total_seconds(), 0)

    def test_duration_to_timedelta_basic(self):
        """Test the most basic case"""
        td = duration_to_timedelta("P1D")
        self.assertEqual(td.total_seconds(), 86400)

    def test_duration_to_timedelta_day_hour(self):
        """Test hour"""
        td = duration_to_timedelta("P1H")
        self.assertEqual(td.total_seconds(), 3600)

    def test_duration_to_timedelta_day_minute(self):
        """Test both day and minute"""
        td = duration_to_timedelta("P1DT1M")
        self.assertEqual(td.total_seconds(), 86460)

    def test_duration_to_timedelta_day_second(self):
        """Test day and second"""
        td = duration_to_timedelta("P1D1")
        self.assertEqual(td.total_seconds(), 86401)

    def test_duration_to_timedelta_second(self):
        """Test second"""
        td = duration_to_timedelta("P11S")
        self.assertEqual(td.total_seconds(), 11)

    def test_duration_to_timedelta_week(self):
        """Test second"""
        td = duration_to_timedelta("P1W")
        self.assertEqual(td.total_seconds(), 86400 * 7)

    def test_bogus(self):
        """Test totally bogus duration"""
        with self.assertRaises(ValueError):
            duration_to_timedelta("foo")

    def test_invalid(self):
        """Test invalid duration"""
        with self.assertRaises(ValueError):
            duration_to_timedelta("Pfoo")


class Test_signers_from_list(TestCase):
    def test_basic(self):
        """Test basic KSR Signer parsing"""
        data = [
            {"attrs": {"keyIdentifier": "KC00020"}, "value": ""},
            {"attrs": {"keyIdentifier": "KC00094"}, "value": ""},
        ]
        out = signers_from_list(data)
        self.assertEqual(
            out, {Signer(key_identifier="KC00020"), Signer(key_identifier="KC00094")}
        )

    def test_no_signer(self):
        """Test that KSR Signer is optional"""
        self.assertIsNone(signers_from_list([]))


class Test_keys_from_list(TestCase):
    def test_basic(self):
        """Test basic KSR Key parsing"""
        data = [
            {
                "attrs": {"keyIdentifier": "ZSK-24315", "keyTag": "24315"},
                "value": {
                    "Algorithm": "5",
                    "Flags": "256",
                    "Protocol": "3",
                    "PublicKey": "A...",
                    "TTL": 1978,
                },
            }
        ]
        out = keys_from_dict(data)
        expected = {
            Key(
                key_identifier="ZSK-24315",
                key_tag=24315,
                ttl=1978,
                flags=256,
                protocol=3,
                algorithm=AlgorithmDNSSEC.RSASHA1,
                public_key=b"A...",
            )
        }
        self.assertEqual(out, expected)

    def test_with_ttl(self):
        """Test Key with TTL"""
        data = [
            {
                "attrs": {"keyIdentifier": "ZSK-24315", "keyTag": "24315"},
                "value": {
                    "Algorithm": "5",
                    "Flags": "256",
                    "Protocol": "3",
                    "PublicKey": "A...",
                    "TTL": "1978",
                },
            }
        ]
        out = keys_from_dict(data)
        expected = {
            Key(
                key_identifier="ZSK-24315",
                key_tag=24315,
                ttl=1978,
                flags=256,
                protocol=3,
                algorithm=AlgorithmDNSSEC.RSASHA1,
                public_key=b"A...",
            )
        }
        self.assertEqual(out, expected)

    def test_ecdsa_key(self):
        """Test loading an ECDSA key"""
        public_key = r"BGuqYyOGr0p/uKXm0MmP4Cuiml/a8FCPRDLerVyBS4jHmJlKTJmYk/nCbOp936DSh5SMu6+2WYJUI6K5AYfXbTE="
        data = [
            {
                "attrs": {"keyIdentifier": "EC1", "keyTag": "0"},
                "value": {
                    "Algorithm": AlgorithmDNSSEC.ECDSAP256SHA256.value,
                    "Flags": "256",
                    "Protocol": "3",
                    "PublicKey": public_key,
                    "TTL": "1978",
                },
            }
        ]
        out = keys_from_dict(data)
        expected = {
            Key(
                key_identifier="EC1",
                key_tag=0,
                ttl=1978,
                flags=256,
                protocol=3,
                algorithm=AlgorithmDNSSEC.ECDSAP256SHA256,
                public_key=public_key.encode(),
            )
        }
        self.assertEqual(out, expected)

        # now change the algorithm and verify that the discrepancy between curve point size and algorithm is detected
        data[0]["value"]["Algorithm"] = AlgorithmDNSSEC.ECDSAP384SHA384.value
        with self.assertRaises(ValueError) as exc:
            keys_from_dict(data)
        self.assertEqual(
            "Unexpected ECDSA key length 256 for algorithm AlgorithmDNSSEC.ECDSAP384SHA384",
            str(exc.exception),
        )


class Test_signature_from_dict(TestCase):
    def test_basic(self):
        """Test basic KSR Signature parsing"""
        sig = {
            "attrs": {"keyIdentifier": "ZSK-24315"},
            "value": {
                "Algorithm": "5",
                "KeyTag": "24315",
                "Labels": "0",
                "OriginalTTL": "3600",
                "SignatureData": "SIG...",
                "SignatureExpiration": "2009-09-24T18:22:41Z",
                "SignatureInception": "2009-08-25T18:22:41Z",
                "SignersName": ".",
                "TypeCovered": "DNSKEY",
                "TTL": 1234,
            },
        }
        out = signature_from_dict(sig)
        utc = datetime.UTC
        expected = {
            Signature(
                key_identifier="ZSK-24315",
                ttl=1234,
                type_covered=TypeDNSSEC.DNSKEY,
                algorithm=AlgorithmDNSSEC.RSASHA1,
                labels=0,
                original_ttl=3600,
                signature_expiration=datetime.datetime(
                    2009, 9, 24, 18, 22, 41, tzinfo=utc
                ),
                signature_inception=datetime.datetime(
                    2009, 8, 25, 18, 22, 41, tzinfo=utc
                ),
                key_tag=24315,
                signers_name=".",
                signature_data=b"SIG...",
            )
        }
        self.assertEqual(out, expected)
