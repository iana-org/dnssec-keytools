from unittest import TestCase

from kskm.common.data import AlgorithmDNSSEC, Key
from kskm.keymaster.inventory import DNSRecords


class Test_DNSRecords(TestCase):
    def test_dns_rrset_formatting(self) -> None:
        """Test formatting of DNS records for a key"""
        public_key = r"BGuqYyOGr0p/uKXm0MmP4Cuiml/a8FCPRDLerVyBS4jHmJlKTJmYk/nCbOp936DSh5SMu6+2WYJUI6K5AYfXbTE="
        key = Key(
            key_identifier="EC1",
            key_tag=12345,
            ttl=1978,
            flags=256,
            protocol=3,
            algorithm=AlgorithmDNSSEC.ECDSAP256SHA256,
            public_key=public_key.encode(),
        )

        dns = DNSRecords.from_key(key)
        formatted = "\n".join(dns.format(indent=0, max_length=100))

        expected = "\n".join(
            [
                ". IN DS 12345 13 2 1918AAC2DE9271647204AF567EFBC2AA685183D7D2A0EE27CB71FD5F202EA10E",
                ". IN DNSKEY 256 3 13 (",
                "    BGuqYyOGr0p/uKXm0MmP4Cuiml/a8FCPRDLerVyBS4jHmJlKTJmYk/nCbOp936DSh5SMu6+2WYJUI6K5AYfXbTE=",
                ")",
            ]
        )
        assert formatted == expected
