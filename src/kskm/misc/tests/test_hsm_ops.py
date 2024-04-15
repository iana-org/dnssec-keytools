"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""

import io
import os
import unittest

from kskm.common.config import KSKMConfig
from kskm.misc.hsm import KSKM_P11, KeyClass, init_pkcs11_modules_from_dict

__author__ = "ft"

_TEST_SOFTHSM2 = bool(
    os.environ.get("SOFTHSM2_MODULE") and os.environ.get("SOFTHSM2_CONF")
)

_TEST_CONFIG = """
---
hsm:
  softhsm:
    module: $SOFTHSM2_MODULE
    pin: 123456
"""


class OperationsWithSoftHSM(unittest.TestCase):
    def setUp(self) -> None:
        """Prepare for tests."""
        self.p11modules: KSKM_P11 = KSKM_P11([])
        conf = io.StringIO(_TEST_CONFIG)
        self.config = KSKMConfig.from_yaml(conf)
        self.p11modules = init_pkcs11_modules_from_dict(self.config.hsm)

    def tearDown(self) -> None:
        """Unload PKCS#11 modules, lest they might not work for the next test that starts."""
        for this in self.p11modules:
            this.close()

    @unittest.skipUnless(_TEST_SOFTHSM2, "SOFTHSM2_MODULE and SOFTHSM2_CONF not set")
    def test_find_key_by_id(self) -> None:
        """Test finding key objects by CKA_ID"""
        module = self.p11modules[0]
        # Well-known CKA_LABEL/CKA_ID for one of the keys loaded into SoftHSM using testing/Makefile
        by_label = module.find_key_by_label("RSA1", KeyClass.PUBLIC)
        assert by_label is not None

        by_id = None
        for _slot, session in module.sessions.items():
            _res = module.find_key_by_id((1,), session)
            if _res:
                for this in _res:
                    if this.pubkey_handle is not None:
                        by_id = this
                        break
                if by_id is not None:
                    break

        assert by_id is not None
        assert by_label.label == by_id.label
        assert by_label.key_type == by_id.key_type
        assert by_label.key_class == by_id.key_class
        assert by_label.public_key == by_id.public_key
