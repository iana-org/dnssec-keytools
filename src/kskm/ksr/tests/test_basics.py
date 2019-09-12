import datetime
import unittest
import xml

from kskm.common.data import SignaturePolicy, AlgorithmPolicyRSA, AlgorithmDNSSEC
from kskm.ksr import request_from_xml


class TestBasics(unittest.TestCase):

    def test_basic_init(self):
        """ Test basic module import """
        import kskm.ksr
        self.assertEqual(kskm.ksr.__author__, 'ft')

    def test_minimal(self):
        """ Test parsing a minimal KSR """
        ksr_xml = '''
<KSR domain="." id="4fe9bb10-6f6b-4503-8575-7824e2d66925" serial="99">
  <Request>
    <RequestPolicy>
      <ZSK>
        <PublishSafety>P10D</PublishSafety>
        <RetireSafety>P11D</RetireSafety>
        <MaxSignatureValidity>P22D</MaxSignatureValidity>
        <MinSignatureValidity>P21D</MinSignatureValidity>
        <MaxValidityOverlap>P12D</MaxValidityOverlap>
        <MinValidityOverlap>P9D</MinValidityOverlap>
        <SignatureAlgorithm algorithm="8">
          <RSA exponent="65537" size="2048"/>
        </SignatureAlgorithm>
      </ZSK>
    </RequestPolicy>
  </Request>
</KSR>'''
        request = request_from_xml(ksr_xml)
        self.assertEqual(request.domain, '.')
        self.assertEqual(request.id, '4fe9bb10-6f6b-4503-8575-7824e2d66925')
        self.assertEqual(request.serial, 99)
        self.assertIsNone(request.timestamp)
        policy = SignaturePolicy(publish_safety=datetime.timedelta(days=10),
                                 retire_safety=datetime.timedelta(days=11),
                                 max_signature_validity=datetime.timedelta(days=22),
                                 min_signature_validity=datetime.timedelta(days=21),
                                 max_validity_overlap=datetime.timedelta(days=12),
                                 min_validity_overlap=datetime.timedelta(days=9),
                                 algorithms={AlgorithmPolicyRSA(bits=2048,
                                                                algorithm=AlgorithmDNSSEC.RSASHA256,
                                                                exponent=65537)},
                                 )
        self.assertEqual(request.zsk_policy, policy)

    def test_ksr_with_timestamp(self):
        """ Test parsing a minimal KSR with the optional timestamp """
        ksr_xml = '''
<KSR domain="." id="4fe9bb10-6f6b-4503-8575-7824e2d66925" serial="99" timestamp="2018-01-01T00:00:00">
  <Request>
    <RequestPolicy>
      <ZSK>
        <PublishSafety>P10D</PublishSafety>
        <RetireSafety>P11D</RetireSafety>
        <MaxSignatureValidity>P22D</MaxSignatureValidity>
        <MinSignatureValidity>P21D</MinSignatureValidity>
        <MaxValidityOverlap>P12D</MaxValidityOverlap>
        <MinValidityOverlap>P9D</MinValidityOverlap>
        <SignatureAlgorithm algorithm="8">
          <RSA exponent="65537" size="2048"/>
        </SignatureAlgorithm>
      </ZSK>
    </RequestPolicy>
  </Request>
</KSR>'''
        request = request_from_xml(ksr_xml)
        self.assertEqual(request.domain, '.')
        self.assertEqual(request.id, '4fe9bb10-6f6b-4503-8575-7824e2d66925')
        self.assertEqual(request.serial, 99)
        self.assertEqual(request.timestamp, datetime.datetime.fromisoformat('2018-01-01T00:00:00+00:00'))
