import os
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from kskm.common.config_misc import RequestPolicy
from kskm.common.signature import validate_signatures
from kskm.ksr import load_ksr, request_from_xml


def archive_dir(extra: str | None = None) -> Path | None:
    """
    Return path to KSR archives, if found using environment variable KSKM_KSR_ARCHIVE_PATH.

    If None is returned, the tests in this module will be skipped.
    """
    _env_dir = os.environ.get("KSKM_KSR_ARCHIVE_PATH")
    if _env_dir is not None:
        _archive_dir = Path(_env_dir)
        if extra:
            _archive_dir = Path(_archive_dir, extra)
        if _archive_dir.is_dir():
            return _archive_dir
    return None


class TestParseRealKSRs(unittest.TestCase):
    def setUp(self) -> None:
        """Prepare test instance"""
        self.data_dir = Path(os.path.dirname(__file__), "data")

    @unittest.skipUnless(archive_dir("ksr"), "KSKM_KSR_ARCHIVE_PATH not set or invalid")
    def test_parse_all_ksrs_in_archive(self) -> None:
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
        # Exception: Failed validating KSR request in file icann-ksr-archive/ksr/ksr-root-2010-q3-2.xml:
        #            Bundle signature expire in the past
        _signature_horizon = 0
        policy = RequestPolicy(
            rsa_exponent_match_zsk_policy=_rsa_exponent_match_zsk_policy,
            rsa_approved_key_sizes=_rsa_approved_key_sizes,
            check_bundle_overlap=_check_bundle_overlap,
            signature_validity_match_zsk_policy=_signature_validity_match_zsk_policy,
            signature_horizon_days=_signature_horizon,
        )

        _dir = archive_dir("ksr")
        assert (
            _dir is not None
        )  # for typing, test would be skipped if archive_dir() returned None
        for fn in sorted(_dir.glob("/*")):
            assert isinstance(fn, str)
            # print('Loading file {}'.format(fn))
            _policy = policy
            if fn.endswith("ksr-root-2016-q3-fallback-1.xml"):
                # Exception: Failed validating KSR request in file ksr-root-2016-q3-fallback-1.xml:
                #            Bundle #8/4183f9f7-d97c-4913-92bf-57ee927c48dc has 1 keys, not 2
                # Exception: Failed validating KSR request in file ksr-root-2016-q3-fallback-1.xml
                #            Unacceptable number of key sets in request 489e60ed-421f-40ff-a80e-ee0a87e0886a,
                #            (2 keys instead of 3)
                _policy = policy.replace(
                    num_keys_per_bundle=[2, 1, 1, 1, 1, 1, 1, 1, 1],
                    num_different_keys_in_all_bundles=2,
                )
            elif fn.endswith("ksr-root-2016-q4-0.xml"):
                # Exception: Failed validating KSR request in file ksr-root-2016-q4-0.xml:
                #            Bundle #2/730b49eb-3dc1-4468-adea-6db09c58a6a3 has 2 keys, not 1
                _policy = policy.replace(
                    num_keys_per_bundle=[2, 2, 2, 1, 1, 1, 1, 1, 2]
                )
            elif fn.endswith("ksr-root-2016-q4-fallback-1.xml"):
                _policy = policy.replace(
                    num_keys_per_bundle=[1, 1, 1, 1, 1, 1, 1, 1, 2],
                    num_different_keys_in_all_bundles=2,
                )

            load_ksr(fn, _policy, raise_original=True)

    @unittest.skipUnless(archive_dir("ksr"), "KSKM_KSR_ARCHIVE_PATH not set or invalid")
    def test_load_and_validate_all_ksrs_in_archive(self) -> None:
        """Parse and validate all the KSRs in the ICANN archive."""
        _dir = archive_dir("ksr")
        assert (
            _dir is not None
        )  # for typing, test would be skipped if archive_dir() returned None
        res = True
        for fn in sorted(_dir.glob("/*")):
            assert isinstance(fn, str)
            try:
                self._test_file(fn)
            except InvalidSignature:
                res = False
        if not res:
            self.fail()

    def _test_file(self, fn: Path, filter_ids: list[str] | None = None) -> None:
        fn = self.data_dir.joinpath(fn)
        with open(fn) as fd:
            xml = fd.read()
        ksr = request_from_xml(xml)
        for bundle in ksr.bundles:
            if filter_ids and bundle.id not in filter_ids:
                continue
            try:
                validate_signatures(bundle)
                print(f"{fn}: Bundle {bundle.id} validated successfully")
            except InvalidSignature:
                print(f"{fn}: Bundle {bundle.id} FAILED validation")
                raise
