import unittest
from datetime import datetime

from kskm.common.config_misc import KSKKey
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY, Key
from kskm.ta.keydigest import create_trustanchor_keydigest


class Test_KeyDigest(unittest.TestCase):
    def test_root_key_2017(self) -> None:
        """Test creating one of the most well known key digests in the world."""
        kskkey = KSKKey(
            algorithm=AlgorithmDNSSEC.RSASHA256,
            description="ICANN key from 2017",
            label="Klajeyz",
            key_tag=1,
            valid_from=datetime.fromisoformat("2017-02-02T00:00:00+00:00"),
        )
        key = Key(
            algorithm=AlgorithmDNSSEC.RSASHA256,
            flags=FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value,
            key_identifier="Klajeyz",
            key_tag=20326,
            public_key=b"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlEx"
            b"OLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr"
            b"3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrD"
            b"K6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws"
            b"9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
            ttl=172800,
            protocol=3,
        )

        # Copy-pasted from https://data.iana.org/root-anchors/root-anchors.xml
        expected = """<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
"""

        keydigest = create_trustanchor_keydigest(kskkey, key)

        self.assertEqual(keydigest.to_xml(), expected)
