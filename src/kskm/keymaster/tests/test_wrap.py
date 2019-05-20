"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""
import datetime
import io
import os
import time
import unittest
from typing import Set

import yaml

from kskm.common.config import ConfigurationError, KSKMConfig
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY, Key
from kskm.common.dnssec import public_key_to_dnssec_key
from kskm.common.parse_utils import parse_datetime, signature_policy_from_dict
from kskm.common.signature import validate_signatures
from kskm.keymaster.delete import wrapkey_delete, key_delete
from kskm.keymaster.keygen import generate_wrapping_key, generate_ec_key, generate_rsa_key
from kskm.keymaster.wrap import key_backup, key_restore
from kskm.ksr import Request
from kskm.ksr.data import RequestBundle
from kskm.misc.hsm import KSKM_P11, get_p11_key, init_pkcs11_modules_from_dict, sign_using_p11
from kskm.signer import sign_bundles
from kskm.signer.key import KeyUsagePolicy_Violation
from kskm.signer.sign import CreateSignatureError

__author__ = 'ft'

if os.environ.get('SOFTHSM2_MODULE') and os.environ.get('SOFTHSM2_CONF'):
    _TEST_SOFTHSM2 = True
else:
    _TEST_SOFTHSM2 = False


_TEST_CONFIG = """
---
hsm:
  softhsm:
    module: $SOFTHSM2_MODULE
    pin: 123456
"""


class Test_Full_Wrapping_Cycle(unittest.TestCase):

    def setUp(self) -> None:
        """ Prepare for tests. """
        self.p11modules: KSKM_P11 = KSKM_P11([])
        conf = io.StringIO(_TEST_CONFIG)
        self.config = KSKMConfig.from_yaml(conf)
        self.p11modules = init_pkcs11_modules_from_dict(self.config.hsm, rw_session=True)

    def tearDown(self) -> None:
        """Unload PKCS#11 modules, lest they might not work for the next test that starts."""
        for this in self.p11modules:
            this.close()

    @unittest.skipUnless(_TEST_SOFTHSM2, 'SOFTHSM2_MODULE and SOFTHSM2_CONF not set')
    def test_full_wrapping_cycle(self) -> None:
        """Test generating a key, wrapping it, deleting it and then restoring it."""

        # Generate a new wrapping key
        wrap_label = f'wrap_test_{int(time.time())}'
        alg = 'AES256'
        res = generate_wrapping_key(wrap_label, alg, self.p11modules)
        if res is not True:
            self.fail('Failed generating a new wrapping key')

        # Generate a new signing key
        flags = FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
        p11key = generate_rsa_key(flags, 512, self.p11modules)
        if not p11key:
            self.fail('Failed generating signing key')
        label = p11key.label

        # Save a signature made with the key before deletion
        _secret_key = get_p11_key(label, self.p11modules, public=False)
        signed1 = sign_using_p11(_secret_key, b'before delete', AlgorithmDNSSEC.RSASHA256)

        wrapped_key = key_backup(label, wrap_label, alg, self.p11modules)
        if not wrapped_key:
            self.fail('Failed wrapping (backing up) the signing key')

        res = key_delete(label, self.p11modules, force=True)
        if res is not True:
            self.fail('Failed deleting the signing key')

        # make sure the signing key is now gone
        _key = get_p11_key(label, self.p11modules, public=True)
        if _key:
            self.fail('The signing key was not properly deleted')

        res = key_restore(wrapped_key, label, wrap_label, alg, self.p11modules)
        if not res:
            self.fail('Failed unwrapping (restoring) the signing key')

        _secret_key = get_p11_key(label, self.p11modules, public=False)
        signed2 = sign_using_p11(_secret_key, b'after restore', AlgorithmDNSSEC.RSASHA256)

        # Delete the signing key generated for this test
        res = key_delete(label, self.p11modules, force=True)
        if res is not True:
            self.fail('Failed deleting the signing key the second time')

        # Delete the wrapping key generated for this test
        res = wrapkey_delete(wrap_label, self.p11modules, force=True)
        if res is not True:
            self.fail('Failed deleting the wrapping key')
