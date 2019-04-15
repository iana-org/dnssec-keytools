"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""

import io
import os
import unittest

from kskm.common.config import KSKMConfig
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.signature import validate_signatures
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, get_p11_key, init_pkcs11_modules_from_dict
from kskm.signer import sign_bundles

if os.environ.get('SOFTHSM2_MODULE') and os.environ.get('SOFTHSM2_CONF'):
    _TEST_SOFTHSM2 = True
else:
    _TEST_SOFTHSM2 = False


_TEST_CONFIG_SIMPLE_RSA = """
---
keys:
  zsk_test_key:
    description: A SoftHSM key used in tests
    label: RSA1
    algorithm: RSASHA256
    rsa_size: 2048
    rsa_exponent: 65537
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00

  ksk_test_key:
    description: A SoftHSM key used in tests
    label: RSA2
    algorithm: RSASHA256
    rsa_size: 2048
    rsa_exponent: 65537
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00
"""

_TEST_CONFIG_SIMPLE_EC = """
---
keys:
  zsk_test_key:
    description: A SoftHSM key used in tests
    label: EC1
    algorithm: ECDSAP256SHA256
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00

  ksk_test_key:
    description: A SoftHSM key used in tests
    label: EC2
    algorithm: ECDSAP256SHA256
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00
"""

_TEST_CONFIG_SIMPLE_COMMON = """
hsm:
  softhsm:
    module: $SOFTHSM2_MODULE
    pin: 123456

schemas:
  test:
    1: {publish: [], sign: ksk_test_key}
    2: {publish: [], sign: ksk_test_key}
    3: {publish: [], sign: ksk_test_key}
    4: {publish: [], sign: ksk_test_key}
    5: {publish: [], sign: ksk_test_key}
    6: {publish: [], sign: ksk_test_key}
    7: {publish: [], sign: ksk_test_key}
    8: {publish: [], sign: ksk_test_key}
    9: {publish: [], sign: ksk_test_key}

ksk_policy:
  publish_safety: PT0S
  retire_safety: P28D
  max_signature_validity: P21D
  min_signature_validity: P21D
  max_validity_overlap: P16D
  min_validity_overlap: P9D
  ttl: 20
"""


class Test_SignWithSoftHSM_RSA(unittest.TestCase):

    def setUp(self) -> None:
        """ Prepare for tests. """
        # CKA_LABEL for one of the keys loaded into SoftHSM using testing/Makefile
        self.zsk_key_label = 'RSA1'
        self.ksk_key_label = 'RSA2'
        self.p11modules: KSKM_P11 = KSKM_P11([])
        conf = io.StringIO(_TEST_CONFIG_SIMPLE_RSA + _TEST_CONFIG_SIMPLE_COMMON)
        self.config = KSKMConfig.from_yaml(conf)
        self.p11modules = init_pkcs11_modules_from_dict(self.config.hsm)
        self.schema = self.config.get_schema('test')
        _policy = {'PublishSafety': 'P10D',
                   'RetireSafety': 'P10D',
                   'MaxSignatureValidity': 'P20D',
                   'MinSignatureValidity': 'P15D',
                   'MaxValidityOverlap': 'P5D',
                   'MinValidityOverlap': 'P5D',
                   'SignatureAlgorithm': {'attrs': {'algorithm': '8'},
                                          'value': {'RSA': {'attrs': {'size': '1024', 'exponent': '3'}, 'value': ''}
                                                    }
                                          }
                   }
        self.signature_policy = signature_policy_from_dict(_policy)

    def tearDown(self) -> None:
        for this in self.p11modules:
            this.close()

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_sign_with_softhsm(self) -> None:
        """ Test signing a key record with SoftHSM and then verifying it """
        if not self.p11modules:
            self.skipTest('No HSM config')
        p11_key = get_p11_key(self.ksk_key_label, self.p11modules, public=True)
        if not p11_key:
            self.fail(f'Key {self.ksk_key_label} not found')
        ksk_key = public_key_to_dnssec_key(key=p11_key.public_key,
                                           key_identifier=self.ksk_key_label,
                                           algorithm=AlgorithmDNSSEC.RSASHA256,
                                           flags=FlagsDNSKEY.SEP.value,  # SEP bit set for KSK
                                           ttl=10,
                                           )
        bundle = RequestBundle(id='test-01',
                               inception=parse_datetime('2018-01-01T00:00:00+00:00'),
                               expiration=parse_datetime('2018-01-22T00:00:00+00:00'),
                               keys={ksk_key},
                               signatures=set(),
                               signers=None,
                               )
        request = Request(id='test-req-01',
                          serial=1,
                          domain='.',
                          bundles=[bundle],
                          zsk_policy=self.signature_policy,
                          )
        new_bundles = sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                                   config=self.config, ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])


class Test_SignWithSoftHSM_ECDSA(unittest.TestCase):

    def setUp(self) -> None:
        """ Prepare for tests. """
        # CKA_LABEL for one of the keys loaded into SoftHSM using testing/Makefile
        self.zsk_key_label = 'EC1'
        self.ksk_key_label = 'EC2'
        self.p11modules: KSKM_P11 = KSKM_P11([])
        conf = io.StringIO(_TEST_CONFIG_SIMPLE_EC + _TEST_CONFIG_SIMPLE_COMMON)
        self.config = KSKMConfig.from_yaml(conf)
        self.p11modules = init_pkcs11_modules_from_dict(self.config.hsm)
        self.schema = self.config.get_schema('test')
        _policy = {'PublishSafety': 'P10D',
                   'RetireSafety': 'P10D',
                   'MaxSignatureValidity': 'P20D',
                   'MinSignatureValidity': 'P15D',
                   'MaxValidityOverlap': 'P5D',
                   'MinValidityOverlap': 'P5D',
                   'SignatureAlgorithm': {'attrs': {'algorithm': '13'},
                                          'value': {'ECDSA': {'attrs': {'size': '256'}, 'value': ''}
                                                    }
                                          }
                   }
        self.signature_policy = signature_policy_from_dict(_policy)

    def tearDown(self) -> None:
        for this in self.p11modules:
            this.close()

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_ec_sign_with_softhsm(self) -> None:
        """ Test ECDSA signing a key record with SoftHSM and then verifying it """
        if not self.p11modules:
            self.skipTest('No HSM config')
        p11_key = get_p11_key(self.ksk_key_label, self.p11modules, public=True)
        if not p11_key:
            self.fail('Key not found')
        ksk_key = public_key_to_dnssec_key(key=p11_key.public_key,
                                           key_identifier=self.ksk_key_label,
                                           algorithm=AlgorithmDNSSEC.ECDSAP256SHA256,
                                           flags=FlagsDNSKEY.SEP.value,  # SEP bit set for KSK
                                           ttl=10,
                                           )
        bundle = RequestBundle(id='test-01',
                               inception=parse_datetime('2018-01-01T00:00:00+00:00'),
                               expiration=parse_datetime('2018-01-22T00:00:00+00:00'),
                               keys={ksk_key},
                               signatures=set(),
                               signers=None,
                               )
        request = Request(id='test-req-01',
                          serial=1,
                          domain='.',
                          bundles=[bundle],
                          zsk_policy=self.signature_policy,
                          )
        new_bundles = sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                                   config=self.config, ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])
