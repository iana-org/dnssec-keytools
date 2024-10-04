import unittest
from binascii import unhexlify
from datetime import datetime

from kskm.common.data import AlgorithmDNSSEC
from kskm.ta.data import DigestDNSSEC, KeyDigest, TrustAnchor

TA_2024_XML = """<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="E9724F53-1851-4F86-85E5-F1392102940B" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
<KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
<KeyTag>38696</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
</KeyDigest>
</TrustAnchor>"""

DIGEST_2010 = KeyDigest(
    id="Kjqmt7v",
    valid_from=datetime.fromisoformat("2010-07-15T00:00:00+00:00"),
    valid_until=datetime.fromisoformat("2019-01-11T00:00:00+00:00"),
    key_tag=19036,
    algorithm=AlgorithmDNSSEC(8),
    digest_type=DigestDNSSEC(2),
    digest=unhexlify(
        "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
    ),
)

DIGEST_2017 = KeyDigest(
    id="Klajeyz",
    valid_from=datetime.fromisoformat("2017-02-02T00:00:00+00:00"),
    key_tag=20326,
    algorithm=AlgorithmDNSSEC(8),
    digest_type=DigestDNSSEC(2),
    digest=unhexlify(
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ),
)

DIGEST_2024 = KeyDigest(
    id="Kmyv6jo",
    valid_from=datetime.fromisoformat("2024-07-18T00:00:00+00:00"),
    key_tag=38696,
    algorithm=AlgorithmDNSSEC(8),
    digest_type=DigestDNSSEC(2),
    digest=unhexlify(
        "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    ),
)

TA_2024 = TrustAnchor(
    id="E9724F53-1851-4F86-85E5-F1392102940B",
    source="http://data.iana.org/root-anchors/root-anchors.xml",
    zone=".",
    key_digests={DIGEST_2010, DIGEST_2017, DIGEST_2024},
)


class Test_TA(unittest.TestCase):
    # no idea why mypy complains about this function without the "-> None" and no other tests
    # src/kskm/ta/tests/test_ta.py:54: error: Function is missing a type annotation
    def test_ta(self) -> None:
        """Test output of Trust Anchor as XML"""
        self.maxDiff = None
        self.assertEqual(TA_2024.to_xml_doc(), TA_2024_XML)


if __name__ == "__main__":
    unittest.main()
