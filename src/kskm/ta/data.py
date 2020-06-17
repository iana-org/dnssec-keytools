"""Trust Anchor Classes (representing TA per RFC 7958)."""

from binascii import hexlify
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Set

from kskm.common.data import AlgorithmDNSSEC


class DigestDNSSEC(Enum):
    SHA1 = 1
    SHA256 = 2


@dataclass(frozen=True)
class KeyDigest:
    id: str
    key_tag: int
    algorithm: AlgorithmDNSSEC
    digest_type: DigestDNSSEC
    digest: bytes
    valid_from: datetime
    valid_until: Optional[datetime] = None

    @classmethod
    def format_datetime(cls, dt: datetime) -> str:
        """Return datetime as xsd:dateTime."""
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def hexdigest(self) -> str:
        """Return key digest as hex."""
        return hexlify(self.digest).decode().upper()

    def to_xml(self) -> str:
        """Return KeyDigest as XML sniplet."""
        xml = f'<KeyDigest id="{self.id}"'
        xml += f' validFrom="{self.format_datetime(self.valid_from)}"'
        if self.valid_until is not None:
            xml += f' validUntil="{self.format_datetime(self.valid_until)}"'
        xml += ">\n"
        xml += f"<KeyTag>{self.key_tag}</KeyTag>\n"
        xml += f"<Algorithm>{self.algorithm.value}</Algorithm>\n"
        xml += f"<DigestType>{self.digest_type.value}</DigestType>\n"
        xml += f"<Digest>{self.hexdigest()}</Digest>\n"
        xml += "</KeyDigest>\n"
        return xml


@dataclass(frozen=True)
class TrustAnchor:
    id: str
    source: str
    zone: str
    keydigests: Set[KeyDigest]

    def to_xml_doc(self) -> str:
        """Export trust anchor as XML document."""
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += self.to_xml()
        return xml

    def to_xml(self) -> str:
        """Export trust anchor as XML sniplet."""
        xml = f'<TrustAnchor id="{self.id}" source="{self.source}">\n'
        xml += f"<Zone>{self.zone}</Zone>\n"
        for ks in sorted(self.keydigests, key=lambda _ks: _ks.valid_from):
            xml += ks.to_xml()
        xml += "</TrustAnchor>"
        return xml
