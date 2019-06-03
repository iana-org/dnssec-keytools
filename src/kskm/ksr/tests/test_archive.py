import glob
import os
import unittest

import pkg_resources
from cryptography.exceptions import InvalidSignature

from kskm.common.config_misc import RequestPolicy
from kskm.common.signature import validate_signatures
from kskm.ksr import load_ksr, request_from_xml


def archive_dir(extra=None):
    """
    Return path to KSR archives, if found using environment variable KSKM_KSR_ARCHIVE_PATH.

    If None is returned, the tests in this module will be skipped.
    """
    _archive_dir = os.environ.get('KSKM_KSR_ARCHIVE_PATH')
    if _archive_dir is not None:
        if extra:
            _archive_dir = os.path.join(_archive_dir, extra)
        if os.path.isdir(_archive_dir):
            return _archive_dir


class TestParseRealKSRs(unittest.TestCase):

    def setUp(self):
        """ Prepare test instance """
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')

    @unittest.skipUnless(archive_dir('ksr'), 'KSKM_KSR_ARCHIVE_PATH not set or invalid')
    def test_parse_all_ksrs_in_archive(self):
        """Parse (but do not validate) all the KSRs in the ICANN archive."""
        # Create a policy that allows some errors that are present in one or more of the historical KSRs.
        #
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Key 302c312a302806035504031321566572695369676e20444e5353656320526f6f742054455354205a534b20312d33 in
        #            bundle 755af55c-e9fd-4a4d-9335-212647115222 has exponent 65537, but ZSK SignaturePolicy says 3
        _rsa_exponent_match_zsk_policy = False
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Key 302c312a302806035504031321566572695369676e20444e5353656320526f6f742054455354205a534b20312d34
        #            in bundle 755af55c-e9fd-4a4d-9335-212647115222 is RSA-1024, but policy dictates [2048]
        _rsa_approved_key_sizes = [1024, 2048]
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle "id=2f50e951 2010-07-11->2010-07-25" overlap 4 days, 23:59:59 with
        #                   "id=755af55c 2010-07-01->2010-07-15" is < claimed minimum 5 days
        _check_bundle_overlap = False
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle validity 14 days, 23:59:59 < claimed min_signature_validity 15 days
        #            (in bundle 755af55c-e9fd-4a4d-9335-212647115222)
        _signature_validity_match_zsk_policy = False
        policy = RequestPolicy(rsa_exponent_match_zsk_policy=_rsa_exponent_match_zsk_policy,
                               rsa_approved_key_sizes=_rsa_approved_key_sizes,
                               check_bundle_overlap=_check_bundle_overlap,
                               signature_validity_match_zsk_policy=_signature_validity_match_zsk_policy,
                               )

        dir = archive_dir('ksr')
        for fn in sorted(glob.glob(dir + '/*')):
            print('Loading file {}'.format(fn))
            load_ksr(fn, policy)

    @unittest.skipUnless(archive_dir('ksr'), 'KSKM_KSR_ARCHIVE_PATH not set or invalid')
    def test_load_and_validate_all_ksrs_in_archive(self):
        """Parse and validate all the KSRs in the ICANN archive."""
        dir = archive_dir('ksr')
        res = True
        for fn in sorted(glob.glob(dir + '/*')):
            try:
                self._test_file(fn)
            except InvalidSignature:
                res = False
        if not res:
            self.fail()

    def _test_file(self, fn, filter=None):
        fn = os.path.join(self.data_dir, fn)
        with open(fn, 'r') as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if filter and bundle.id not in filter:
                continue
            try:
                validate_signatures(bundle)
                print('{}: Bundle {} validated successfully'.format(fn, bundle.id))
            except InvalidSignature:
                print('{}: Bundle {} FAILED validation'.format(fn, bundle.id))
                raise
