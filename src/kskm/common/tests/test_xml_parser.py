import unittest

from kskm.common.xml_parser import parse


class TestXMLParser(unittest.TestCase):
    def test_shortest_possible(self):
        """Test parsing XML with only one element"""
        xml = """
        <KSR id="foo">hello</KSR>
        """
        parsed = parse(xml)
        expected = {"KSR": {"attrs": {"id": "foo"}, "value": "hello"}}
        self.assertEqual(parsed, expected)

    def test_basic_xml_parser(self):
        """Test parsing the very most basic KSR XML"""
        xml = """
                <KSR id="46E2A89A-91A4-11DE-9606-D3C665893CB7" domain=".">
                 <Request>
                  <RequestPolicy>
                   <ZSK>
                    <PublishSafety>P14D</PublishSafety>
                    <RetireSafety>P7D</RetireSafety>
                   </ZSK>
                  </RequestPolicy>
                 </Request>
                </KSR>
                """
        parsed = parse(xml)
        expected = {
            "KSR": {
                "attrs": {"id": "46E2A89A-91A4-11DE-9606-D3C665893CB7", "domain": "."},
                "value": {
                    "Request": {
                        "RequestPolicy": {
                            "ZSK": {"PublishSafety": "P14D", "RetireSafety": "P7D"}
                        }
                    }
                },
            }
        }
        self.assertEqual(parsed, expected)

    def test_multiple_bundles(self):
        """Test parsing a rather basic KSR XML with multiple RequestBundle"""
        xml = """
                <KSR>
                 <Request>
                  <RequestBundle id="46E2E616-91A4-11DE-AC37-E3B2CDA0AB07">
                   <Inception>2009-08-25T20:22:41Z</Inception>
                  </RequestBundle>
                  <RequestBundle id="46EB9FD6-91A4-11DE-8B81-926F6A39C94A">
                   <Inception>2009-09-01T20:22:41Z</Inception>
                  </RequestBundle>
                 </Request>
                </KSR>
                """
        parsed = parse(xml)
        expected = {
            "KSR": {
                "Request": {
                    "RequestBundle": [
                        {
                            "attrs": {"id": "46E2E616-91A4-11DE-AC37-E3B2CDA0AB07"},
                            "value": {"Inception": "2009-08-25T20:22:41Z"},
                        },
                        {
                            "attrs": {"id": "46EB9FD6-91A4-11DE-8B81-926F6A39C94A"},
                            "value": {"Inception": "2009-09-01T20:22:41Z"},
                        },
                    ],
                }
            }
        }
        self.assertEqual(parsed, expected)

    def test_signer(self):
        """Test parsing a rather basic KSR XML with Signer elements that have no value"""
        xml = """
                <KSR>
                  <Signer keyIdentifier="KC00020" />
                  <Signer keyIdentifier="KC00094" />
                </KSR>
                """
        parsed = parse(xml)
        expected = {
            "KSR": {
                "Signer": [
                    {"attrs": {"keyIdentifier": "KC00020"}, "value": ""},
                    {"attrs": {"keyIdentifier": "KC00094"}, "value": ""},
                ],
            }
        }
        self.assertEqual(parsed, expected)

    def test_nested_tags(self):
        """Test parsing of nested Signature tags"""
        xml = """
        <KSR>
          <Signature keyIdentifier="ZSK-24315">
            <KeyTag>24315</KeyTag>
            <Signature>WL7ks0TL...</Signature>
          </Signature>
        </KSR>"""
        parsed = parse(xml)
        expected = {
            "KSR": {
                "Signature": {
                    "attrs": {"keyIdentifier": "ZSK-24315"},
                    "value": {
                        "KeyTag": "24315",
                        "Signature": "WL7ks0TL...",
                    },
                }
            }
        }
        self.assertEqual(parsed, expected)

    def test_invalid_tag(self):
        """Test parsing of XML with an invalid tag"""
        xml = """
        <KSR>
          <Signature
        </KSR>"""
        with self.assertRaises(ValueError) as cm:
            parse(xml)
        self.assertEqual(str(cm.exception), "Failed parsing tag '<Signature'...")

    def test_trailing_data(self):
        """Test parsing of XML with non-XML data after it"""
        xml = """
        <KSR>
        </KSR>fail"""
        with self.assertRaises(ValueError) as cm:
            parse(xml)
        self.assertEqual(str(cm.exception), "XML parser got lost at: 'fail'")

    def test_too_much_recursuin(self):
        """Test parsing of XML with too many nested levels"""
        xml = """
        <a><b><c><d><e><ft>testing</ft></e></d></c></b></a>
        """
        with self.assertRaises(ValueError) as cm:
            parse(xml, recurse=3)
        self.assertEqual(str(cm.exception), "XML maximum recursion depth exhausted")

        # now try again with a higher recursion depth allowed
        out = parse(xml, recurse=10)
        expected = {"a": {"b": {"c": {"d": {"e": {"ft": "testing"}}}}}}
        self.assertEqual(out, expected)
