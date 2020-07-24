"""
These tests only works if SOFTHSM2_MODULE and SOFTHSM2_CONF is set.

Set SOFTHSM2_MODULE to the SoftHSM PKCS#11 and SOFTHSM2_CONF to the configuration
file *with the test keys created using 'make softhsm' in th testing/softhsm/ loaded*.
"""
import io
import os
import unittest

from kskm.common.config import KSKMConfig
from kskm.keymaster.inventory import key_inventory
from kskm.misc.hsm import KSKM_P11, init_pkcs11_modules_from_dict

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


class Test_Key_Inventory(unittest.TestCase):
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
    def test_inventory(self):
        res = key_inventory(self.p11modules, self.config)
        # key inventory is expected to be at least 10 (15) lines when loaded with
        # the test keys from testing/softhsm/Makefile.
        self.assertGreater(len(res), 10)
        output_str = "\n".join(res)
        # check for two well known key labels
        self.assertIn("RSA1", output_str)
        self.assertIn("EC1", output_str)
