import os
from pathlib import Path

from pytest import LogCaptureFixture

import kskm.tools.keymaster as keymaster
from kskm.tools import EXIT_CODES


class TestKeymaster:
    def test_missing_configuration(self, caplog: LogCaptureFixture) -> None:
        assert keymaster.main("testing", ["--config", "not_my_config.yaml", "inventory"]) == EXIT_CODES.fatal
        assert "No such file or directory: 'not_my_config.yaml'" in caplog.text

    def test_load_invalid_config(self, caplog: LogCaptureFixture) -> None:
        """Test the claim that an invalid policy is rejected by keymaster.py"""
        # #### Argument (1.1.1.3)
        # ...
        # Test cases provides evidence that if a policy is rejected, 'ConfigurationError' is raised and the load
        # configuration procedure in main of 'keymaster.py' will return 'False'.
        data_dir = Path(os.path.dirname(__file__), "data")
        fn = data_dir.joinpath("keymaster_bad_policy.yaml")
        assert keymaster.main("testing", ["--config", str(fn), "inventory"]) == EXIT_CODES.config
        assert "num_bundles must be a positive integer" in caplog.text
