"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""
import io
import os
import time
import unittest

from kskm.common.config import KSKMConfig
from kskm.common.data import AlgorithmDNSSEC, FlagsDNSKEY
from kskm.keymaster.delete import key_delete, wrapkey_delete
from kskm.keymaster.keygen import generate_rsa_key, generate_wrapping_key
from kskm.keymaster.wrap import key_backup, key_restore
from kskm.misc.hsm import (
    KSKM_P11,
    WrappingAlgorithm,
    get_p11_key,
    init_pkcs11_modules_from_dict,
    sign_using_p11,
)
from kskm.signer.sign import _verify_using_crypto

__author__ = "ft"

if os.environ.get("SOFTHSM2_MODULE") and os.environ.get("SOFTHSM2_CONF"):
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
        self.p11modules = init_pkcs11_modules_from_dict(
            self.config.hsm, rw_session=True
        )

    def tearDown(self) -> None:
        """Unload PKCS#11 modules, lest they might not work for the next test that starts."""
        for this in self.p11modules:
            this.close()

    @unittest.skipUnless(_TEST_SOFTHSM2, "SOFTHSM2_MODULE and SOFTHSM2_CONF not set")
    @unittest.skipIf(
        os.environ.get("TEST_SOFTHSM2_SKIP_KEYWRAP"),
        "Skipping keywrap test because TEST_SOFTHSM2_SKIP_KEYWRAP is set",
    )
    def test_full_wrapping_cycle(self) -> None:
        """Test generating a key, wrapping it, deleting it and then restoring it."""

        # Generate a new wrapping key
        wrap_label = f"wrap_test_{int(time.time())}"
        alg = WrappingAlgorithm["AES256"]
        res = generate_wrapping_key(wrap_label, alg, self.p11modules)
        if res is not True:
            self.fail("Failed generating a new wrapping key")

        # Generate a new signing key
        flags = FlagsDNSKEY.ZONE.value | FlagsDNSKEY.SEP.value
        p11key = generate_rsa_key(flags, 1024, self.p11modules)
        if not p11key:
            self.fail("Failed generating signing key")
        _pubkey_attrs1 = p11key.pubkey_handle[0].to_dict()
        label = p11key.label

        # Save a signature made with the key before deletion
        _secret_key1 = get_p11_key(label, self.p11modules, public=False)
        _privkey_attrs1 = _secret_key1.privkey_handle[0].to_dict()
        msg1 = b"before delete"
        signed1 = sign_using_p11(_secret_key1, msg1, AlgorithmDNSSEC.RSASHA256)
        _verify_using_crypto(p11key, msg1, signed1, AlgorithmDNSSEC.RSASHA256)

        wrapped_key = key_backup(label, wrap_label, self.p11modules)
        if not wrapped_key:
            self.fail("Failed wrapping (backing up) the signing key")

        res = key_delete(label, self.p11modules, force=True)
        if res is not True:
            self.fail("Failed deleting the signing key")

        # make sure the signing key is now gone
        _key = get_p11_key(label, self.p11modules, public=True)
        if _key:
            self.fail("The signing key was not properly deleted")

        res = key_restore(wrapped_key, self.p11modules)
        if not res:
            self.fail("Failed unwrapping (restoring) the signing key")

        # Validate signatures created both before and after restore using the recreated public key
        _secret_key2 = get_p11_key(label, self.p11modules, public=False)
        _privkey_attrs2 = _secret_key2.privkey_handle[0].to_dict()
        msg2 = b"after restore"
        signed2 = sign_using_p11(_secret_key2, msg2, AlgorithmDNSSEC.RSASHA256)
        _verify_using_crypto(p11key, msg2, signed2, AlgorithmDNSSEC.RSASHA256)
        # now verify the previous signature again using the restored public key
        restored_p11key = get_p11_key(label, self.p11modules, public=True)
        _pubkey_attrs2 = restored_p11key.pubkey_handle[0].to_dict()
        _verify_using_crypto(restored_p11key, msg1, signed1, AlgorithmDNSSEC.RSASHA256)

        # Check that the public key appears the same after restore
        self.assertEqual(_secret_key1.public_key, _secret_key2.public_key)
        # Remove CKA_LOCAL, CKA_KEY_GEN_MECHANISM and CKA_ALWAYS_SENSITIVE which are expected
        # to change between key generated on token, and key created with C_CreateObject
        for _attrs in [
            _pubkey_attrs1,
            _pubkey_attrs2,
            _privkey_attrs1,
            _privkey_attrs2,
        ]:
            for key in ["CKA_LOCAL", "CKA_KEY_GEN_MECHANISM", "CKA_ALWAYS_SENSITIVE"]:
                _attrs.pop(key, None)
        self.maxDiff = None
        self.assertDictEqual(_pubkey_attrs1, _pubkey_attrs2)
        self.assertDictEqual(_privkey_attrs1, _privkey_attrs2)

        # Delete the signing key generated for this test
        res = key_delete(label, self.p11modules, force=True)
        if res is not True:
            self.fail("Failed deleting the signing key the second time")

        # Delete the wrapping key generated for this test
        res = wrapkey_delete(wrap_label, self.p11modules, force=True)
        if res is not True:
            self.fail("Failed deleting the wrapping key")
