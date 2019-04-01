"""
These tests only run if TEST_HSMCONFIG_DIR is set.

Point that environment variable to a directory with an .hsmconfig file allowing
initialisation of SoftHSM2 *with the test keys created using 'make softhsm' in th
testing/softhsm/ loaded*.

Example ${TEST_HSMCONFIG_DIR}/test.hsmconfig file:

  SOFTHSM2_CONF=/path/to/icann-kskm/testing/softhsm/softhsm.conf
  PKCS11_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so
"""

import os
import io
import unittest

from dataclasses import replace


from kskm.misc.hsm import *
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.common.data import Signature, Key, Bundle, AlgorithmDNSSEC, FlagsDNSKEY, SignaturePolicy
from kskm.common.signature import validate_signatures
from kskm.common.rsa_utils import RSAPublicKeyData, encode_rsa_public_key, public_key_to_dnssec_key
from kskm.common.dnssec import calculate_key_tag
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.config import load_from_yaml, get_schema, get_ksk_policy
from kskm.signer import sign_bundles


_TEST_HSMCONFIG_DIR = os.environ.get('TEST_HSMCONFIG_DIR')

_TEST_CONFIG_SIMPLE = """
---
keys:
  zsk_test_key:
    description: A SoftHSM key used in tests
    label: KEY1
    algorithm: RSASHA256
    rsa_size: 2048
    rsa_exponent: 65537
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00

  ksk_test_key:
    description: A SoftHSM key used in tests
    label: KEY2
    algorithm: RSASHA256
    rsa_size: 2048
    rsa_exponent: 65537
    valid_from: 2010-07-15T00:00:00+00:00
    valid_until: 2019-01-11T00:00:00+00:00

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


class Test_SignWithSoftHSM(unittest.TestCase):

    def setUp(self) -> None:
        # CKA_LABEL for one of the keys loaded into SoftHSM using testing/Makefile
        self.zsk_key_label = 'KEY1'
        self.ksk_key_label = 'KEY2'
        self.p11modules: KSKM_P11 = KSKM_P11([])
        if _TEST_HSMCONFIG_DIR:
            self.p11modules = init_pkcs11_modules(_TEST_HSMCONFIG_DIR)
            if not self.p11modules:
                self.fail(f'Failed loading PKCS#11 modules from .hsmconfig in {_TEST_HSMCONFIG_DIR}')
        conf = io.StringIO(_TEST_CONFIG_SIMPLE)
        self.config = load_from_yaml(conf)
        self.schema = get_schema('test', self.config)
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


    @unittest.skipUnless(_TEST_HSMCONFIG_DIR, 'TEST_HSMCONFIG_DIR not set')
    def test_sign_with_softhsm(self) -> None:
        """ Test signing a key record with SoftHSM and then verifying it """
        p11_key = get_p11_key(self.ksk_key_label, self.p11modules, public=True)
        if not p11_key:
            self.fail('Key not found')
        ksk_key = public_key_to_dnssec_key(key=p11_key.public_key,
                                           key_identifier=self.ksk_key_label,
                                           algorithm=AlgorithmDNSSEC.RSASHA256,
                                           flags=FlagsDNSKEY.SEP.value,  # SEP bit set for KSK
                                           protocol=3,  # Always 3 for DNSSEC
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
        ksk_policy = get_ksk_policy(self.config)
        new_bundles = sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                                   config=self.config, ksk_policy=ksk_policy)
        validate_signatures(list(new_bundles)[0])
