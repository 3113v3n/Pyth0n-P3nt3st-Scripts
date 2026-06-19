import pytest

from domains.password_module import PasswordModule
from utils.shared.errors import MissingRequiredFileError


def test_require_input_file_raises_custom_error_for_missing_file(tmp_path):
    missing = tmp_path / "missing.txt"
    with pytest.raises(MissingRequiredFileError, match="does not exist"):
        PasswordModule._require_input_file(str(missing), "Password list")
