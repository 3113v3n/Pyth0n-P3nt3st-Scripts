import pytest

from handlers.argument_validation import (
    normalize_domain,
    parse_phase_selection,
    require_regular_file,
    resolve_safe_operator_tag,
)
from utils.shared.errors import MissingRequiredFileError, ModuleArgumentError


def test_require_regular_file_rejects_directory(tmp_path):
    with pytest.raises(MissingRequiredFileError, match="must be a file"):
        require_regular_file(str(tmp_path), "Password list")


def test_require_regular_file_rejects_missing_path(tmp_path):
    missing = tmp_path / "missing.txt"
    with pytest.raises(MissingRequiredFileError, match="does not exist"):
        require_regular_file(str(missing), "Password list")


def test_normalize_domain_strips_scheme_and_trailing_slash():
    assert normalize_domain("https://Example.com/") == "Example.com"
    assert normalize_domain("http://test.example.com") == "test.example.com"


def test_parse_phase_selection_deduplicates_and_preserves_order():
    phases = parse_phase_selection(
        " probe, recon,probe , urls ",
        default_phases=("recon", "probe"),
        valid_phases=("recon", "probe", "urls"),
    )
    assert phases == ("probe", "recon", "urls")


def test_parse_phase_selection_rejects_unknown_phase():
    with pytest.raises(ModuleArgumentError, match="Unknown phase"):
        parse_phase_selection(
            "recon,boom",
            default_phases=("recon", "probe"),
            valid_phases=("recon", "probe"),
        )


def test_resolve_safe_operator_tag_defaults_only_in_safe_mode():
    assert resolve_safe_operator_tag(True, "", "authorized-security-testing") == "authorized-security-testing"
    assert resolve_safe_operator_tag(False, "", "authorized-security-testing") == ""
    assert resolve_safe_operator_tag(True, " analyst01 ", "authorized-security-testing") == "analyst01"
