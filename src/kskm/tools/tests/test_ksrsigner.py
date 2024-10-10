import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pytest import LogCaptureFixture

import kskm.tools.ksrsigner as ksrsigner
from kskm.tools import EXIT_CODES


class TestKSRsigner:
    @patch("kskm.tools.ksrsigner.check_skr_and_ksr")
    @patch("kskm.signer.sign_bundles")
    @patch("kskm.tools.ksrsigner.check_last_skr_and_new_skr")
    @patch("kskm.tools.ksrsigner.output_skr_xml")
    def test_ksrsigner_calls_policy_validation_functions(
        self,
        mock_check_skr_and_ksr: MagicMock,
        mock_sign_bundles: MagicMock,
        mock_check_last_skr_and_new_ksr: MagicMock,
        mock_output_skr_xml: MagicMock,
    ) -> None:
        data_dir = Path(os.path.dirname(__file__), "data")
        config_fn = data_dir.joinpath("ksrsigner.yaml")
        skr_fn = data_dir.joinpath("skr-root-2017-q1-0.xml")
        ksr_fn = data_dir.joinpath("ksr-root-2017-q2-0.xml")

        assert (
            ksrsigner.main(
                "testing",
                [
                    "--config",
                    str(config_fn),
                    "--previous_skr",
                    str(skr_fn),
                    "--force",
                    str(ksr_fn),
                ],
            )
            == EXIT_CODES.success
        )

        mock_check_skr_and_ksr.assert_called_once()
        mock_sign_bundles.assert_called_once()
        mock_check_last_skr_and_new_ksr.assert_called_once()
        mock_output_skr_xml.assert_called_once()

    def test_ksrsigner_policy_violation(self, caplog: LogCaptureFixture) -> None:
        """Test that ksrsigner stops on policy violations"""
        data_dir = Path(os.path.dirname(__file__), "data")
        config_fn = data_dir.joinpath("ksrsigner.yaml")
        skr_fn = data_dir.joinpath("skr-root-2017-q1-0.xml")
        ksr_fn = data_dir.joinpath("ksr-root-2017-q2-0.xml")

        test_reason = "TEST_POLICY_INVALID"

        # Verify that if we mock the check_skr_and_ksr() function to raise a ValueError,
        # execution will stop for this precise reason.
        with pytest.raises(ValueError, match=test_reason), patch("kskm.tools.ksrsigner.check_skr_and_ksr") as mock:
            mock.side_effect = ValueError(test_reason)
            assert (
                ksrsigner.main(
                    "testing",
                    [
                        "--config",
                        str(config_fn),
                        "--previous_skr",
                        str(skr_fn),
                        "--force",
                        str(ksr_fn),
                    ],
                )
                == EXIT_CODES.config
            )
