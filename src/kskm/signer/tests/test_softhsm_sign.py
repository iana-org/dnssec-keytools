"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""
import datetime
import io
import os
import unittest
from typing import Set

import pkg_resources
import yaml

from kskm.common.config import ConfigurationError, KSKMConfig
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY, Key
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.signature import validate_signatures
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, get_p11_key, init_pkcs11_modules_from_dict
from kskm.signer import sign_bundles
from kskm.signer.key import KeyUsagePolicy_Violation
from kskm.signer.sign import CreateSignatureError

__author__ = 'ft'

if os.environ.get('SOFTHSM2_MODULE') and os.environ.get('SOFTHSM2_CONF'):
    _TEST_SOFTHSM2 = True
else:
    _TEST_SOFTHSM2 = False


_TEST_CONFIG = """
schemas:
  test:
    1: {publish: [], sign: ksk_RSA2}
    2: {publish: [], sign: ksk_RSA2}
    3: {publish: [], sign: ksk_RSA2}
    4: {publish: [], sign: ksk_RSA2}
    5: {publish: [], sign: ksk_RSA2}
    6: {publish: [], sign: ksk_RSA2}
    7: {publish: [], sign: ksk_RSA2}
    8: {publish: [], sign: ksk_RSA2}
    9: {publish: [], sign: ksk_RSA2}

ksk_policy:
  publish_safety: PT0S
  retire_safety: P28D
  max_signature_validity: P21D
  min_signature_validity: P21D
  max_validity_overlap: P16D
  min_validity_overlap: P9D
  ttl: 20
"""


class SignWithSoftHSM_Baseclass(unittest.TestCase):

    def setUp(self) -> None:
        """ Prepare for tests. """
        # CKA_LABEL for one of the keys loaded into SoftHSM using testing/Makefile
        self.zsk_key_label = 'RSA1'
        self.ksk_key_label = 'RSA2'
        self.p11modules: KSKM_P11 = KSKM_P11([])
        self.softhsm_dir = pkg_resources.resource_filename(__name__, '../../../../testing/softhsm')
        _cfg_fn = os.path.join(self.softhsm_dir, 'ksrsigner.yaml')

        with open(_cfg_fn, 'r') as fd:
            conf = io.StringIO(fd.read() + _TEST_CONFIG)
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
        self.request_zsk_policy = signature_policy_from_dict(_policy)



    def tearDown(self) -> None:
        """Unload PKCS#11 modules, lest they might not work for the next test that starts."""
        for this in self.p11modules:
            this.close()

    def _p11_to_dnskey(self, key_name: str, algorithm: AlgorithmDNSSEC,
                       flags: int = FlagsDNSKEY.SEP.value | FlagsDNSKEY.ZONE.value):
        if not self.p11modules:
            self.skipTest('No HSM config')
        p11_key = get_p11_key(key_name, self.p11modules, public=True)
        if not p11_key:
            self.fail('Key not found')
        zsk_key = public_key_to_dnssec_key(key=p11_key.public_key,
                                           key_identifier=key_name,
                                           algorithm=algorithm,
                                           flags=flags,
                                           ttl=10,
                                           )
        return zsk_key

    def _make_request(self, zsk_keys: Set[Key], inception=None, expiration=None):
        if inception is None:
            inception = parse_datetime('2018-01-01T00:00:00+00:00')
        if expiration is None:
            expiration = parse_datetime('2018-01-22T00:00:00+00:00')
        bundle = RequestBundle(id='test-01',
                               inception=inception,
                               expiration=expiration,
                               keys=zsk_keys,
                               signatures=set(),
                               signers=None,
                               )
        request = Request(id='test-req-01',
                          serial=1,
                          domain='.',
                          bundles=[bundle],
                          zsk_policy=self.request_zsk_policy,
                          )
        return request


class Test_SignWithSoftHSM_RSA(SignWithSoftHSM_Baseclass):

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_sign_with_softhsm(self) -> None:
        """ Test signing a key record with SoftHSM and then verifying it """
        zsk_keys = {self._p11_to_dnskey(self.ksk_key_label, AlgorithmDNSSEC.RSASHA256)}
        request = self._make_request(zsk_keys=zsk_keys)
        new_bundles = sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                                   config=self.config, ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])


class Test_SignWithSoftHSM_ECDSA(SignWithSoftHSM_Baseclass):

    def setUp(self) -> None:
        """ Prepare for tests. """
        super().setUp()

        _EC_CONF = """---
        schemas:
          test:
            1: {publish: [], sign: ksk_EC2}
            2: {publish: [], sign: ksk_EC2}
            3: {publish: [], sign: ksk_EC2}
            4: {publish: [], sign: ksk_EC2}
            5: {publish: [], sign: ksk_EC2}
            6: {publish: [], sign: ksk_EC2}
            7: {publish: [], sign: ksk_EC2}
            8: {publish: [], sign: ksk_EC2}
            9: {publish: [], sign: ksk_EC2}
        
        keys:
          ksk_EC3:
            description: A SoftHSM key used in tests
            label: EC3
            key_tag: null
            algorithm: ECDSAP256SHA256
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_EC_CONF)))
        self.schema = self.config.get_schema('test')

        # CKA_LABEL for one of the keys loaded into SoftHSM using testing/Makefile
        self.zsk_key_label = 'EC1'
        self.ksk_key_label = 'EC2'

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_ec_sign_with_softhsm(self) -> None:
        """ Test ECDSA signing a key record with SoftHSM and then verifying it """
        zsk_keys = {self._p11_to_dnskey(self.ksk_key_label, AlgorithmDNSSEC.ECDSAP256SHA256)}
        request = self._make_request(zsk_keys=zsk_keys)
        new_bundles = sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                                   config=self.config, ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_ec_sign_rsa_zsk(self) -> None:
        """ Test mismatching algorithms for ZSK and KSK. """
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(CreateSignatureError):
            sign_bundles(request=request, schema=self.schema, p11modules=self.p11modules,
                         config=self.config, ksk_policy=self.config.ksk_policy)

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_ec_sign_prepublish_key(self) -> None:
        """ Test a schema pre-publishing a third key. """
        _PUBLISH_SCHEMA = """---
        schemas:
          test:
            1: {publish: ksk_EC3, sign: ksk_EC2}
            2: {publish: ksk_EC3, sign: ksk_EC2}
            3: {publish: ksk_EC3, sign: ksk_EC2}
            4: {publish: ksk_EC3, sign: ksk_EC2}
            5: {publish: ksk_EC3, sign: ksk_EC2}
            6: {publish: ksk_EC3, sign: ksk_EC2}
            7: {publish: ksk_EC3, sign: ksk_EC2}
            8: {publish: ksk_EC3, sign: ksk_EC2}
            9: {publish: ksk_EC3, sign: ksk_EC2}
        """
        self.config.update(yaml.safe_load(io.StringIO(_PUBLISH_SCHEMA)))
        self.schema = self.config.get_schema('test')
        zsk_keys = {self._p11_to_dnskey('EC1', AlgorithmDNSSEC.ECDSAP256SHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        new_bundles = sign_bundles(request=request, schema=self.config.get_schema('test'),
                                   p11modules=self.p11modules, config=self.config,
                                   ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])
        key_ids = sorted([x.key_identifier for x in list(new_bundles)[0].keys])
        self.assertEqual(key_ids, ['EC1',  # ZSK key in RequestBundle
                                   'EC2',  # ksk_test_key
                                   'EC3',  # ksk_prepublish_key
                                   ])


class Test_SignWithSoftHSM_DualAlgorithm(SignWithSoftHSM_Baseclass):

    def setUp(self) -> None:
        """ Prepare for tests. """
        super().setUp()

        _SCHEMAS = """
        schemas:
          test:
            1: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            2: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            3: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            4: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            5: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            6: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            7: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            8: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
            9: {publish: [], sign: [ksk_EC2, ksk_RSA2]}
        """
        self.config.update(yaml.safe_load(io.StringIO(_SCHEMAS)))

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_single_zsk_dual_ksk(self) -> None:
        """ Test algorithm mismatch with one ZSK algorithm and two KSK algorithms. """
        zsk_keys = {self._p11_to_dnskey('EC1', AlgorithmDNSSEC.ECDSAP256SHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(CreateSignatureError):
            sign_bundles(request=request, schema=self.config.get_schema('test'),
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_ec_sign_prepublish_key(self) -> None:
        """ Test signing a full dual algorithm request. """
        zsk_keys = {self._p11_to_dnskey('EC1', AlgorithmDNSSEC.ECDSAP256SHA256, flags=0),
                    self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)
                    }
        request = self._make_request(zsk_keys=zsk_keys)
        new_bundles = sign_bundles(request=request, schema=self.config.get_schema('test'),
                                   p11modules=self.p11modules, config=self.config,
                                   ksk_policy=self.config.ksk_policy)
        validate_signatures(list(new_bundles)[0])
        key_ids = sorted([x.key_identifier for x in list(new_bundles)[0].keys])
        self.assertEqual(key_ids, ['EC1',
                                   'EC2',
                                   'RSA1',
                                   'RSA2',
                                   ])


class Test_SignWithSoftHSM_Errorhandling(SignWithSoftHSM_Baseclass):

    def test_unknown_key(self):
        """ Test referring to a key that does not exist in the PKCS#11 module (SoftHSM). """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: A key that does not exist in SoftHSM
            label: NO_SUCH_KEY
            key_tag: 15
            algorithm: RSASHA256
            rsa_size: 2048
            rsa_exponent: 65537
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('EC1', AlgorithmDNSSEC.ECDSAP256SHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(ConfigurationError):
            sign_bundles(request=request, schema=self.config.get_schema('test'),
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_not_yet_valid_key(self):
        """ Test referring to a key that is not yet valid. """
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        ksk_key = self.config.ksk_keys['ksk_EC2']
        request = self._make_request(zsk_keys=zsk_keys,
                                     inception=ksk_key.valid_from - datetime.timedelta(days=1),
                                     )
        with self.assertRaises(KeyUsagePolicy_Violation):
            sign_bundles(request=request, schema=self.config.get_schema('test'),
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_expired_key(self):
        """ Test referring to a key that has expired the same second. """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: A key that does not exist in SoftHSM
            label: NO_SUCH_KEY
            key_tag: 15
            algorithm: RSASHA256
            rsa_size: 2048
            rsa_exponent: 65537
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        ksk_key = self.config.ksk_keys['ksk_RSA2']
        request = self._make_request(zsk_keys=zsk_keys,
                                     expiration=ksk_key.valid_until + datetime.timedelta(seconds=1),
                                     )
        with self.assertRaises(KeyUsagePolicy_Violation):
            sign_bundles(request=request, schema=self.config.get_schema('test'),
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_not_an_RSA_key(self):
        """ Test referring to a key that is EC instead of the expected RSA. """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: An EC key with algorithm RSA
            label: EC1
            key_tag: 16
            algorithm: RSASHA256
            rsa_size: 2048
            rsa_exponent: 65537
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(ValueError):
            sign_bundles(request=request, schema=self.schema,
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_RSA_key_wrong_size(self):
        """ Test referring to an RSA key that has incorrect size in the config. """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: An RSA key with wrong size
            label: RSA2
            key_tag: null
            algorithm: RSASHA256
            rsa_size: 1234
            rsa_exponent: 65537
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(ValueError):
            sign_bundles(request=request, schema=self.schema,
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_RSA_key_wrong_exponent(self):
        """ Test referring to an RSA key that has incorrect exponent in the config. """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: An RSA key with wrong exponent
            label: RSA1
            key_tag: null
            algorithm: RSASHA256
            rsa_size: 2048
            rsa_exponent: 17
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(ValueError):
            sign_bundles(request=request, schema=self.schema,
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)

    def test_not_an_EC_key(self):
        """ Test referring to a key that is RSA instead of the expected EC. """
        _BAD_KEYS = """---
        keys:
          ksk_RSA2:
            description: An EC key with algorithm RSA
            label: RSA1
            key_tag: null
            algorithm: ECDSAP256SHA256
            valid_from: 2010-07-15T00:00:00+00:00
            valid_until: 2019-01-11T00:00:00+00:00
        """
        self.config.merge_update(yaml.safe_load(io.StringIO(_BAD_KEYS)))
        zsk_keys = {self._p11_to_dnskey('RSA1', AlgorithmDNSSEC.RSASHA256, flags=0)}
        request = self._make_request(zsk_keys=zsk_keys)
        with self.assertRaises(ValueError):
            sign_bundles(request=request, schema=self.schema,
                         p11modules=self.p11modules, config=self.config,
                         ksk_policy=self.config.ksk_policy)
