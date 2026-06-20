import pytest

from domains.password_module import PasswordModule
from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.shared.errors import MissingRequiredFileError


def test_require_input_file_raises_custom_error_for_missing_file(tmp_path):
    missing = tmp_path / "missing.txt"
    with pytest.raises(MissingRequiredFileError, match="does not exist"):
        PasswordModule._require_input_file(str(missing), "Password list")


def test_generate_password_list_routes_status_to_transcript_when_stdout_is_suppressed(tmp_path, capsys):
    class Harness(PasswordModule):
        def compare_hash_from_dump(self, cracked_hashes, dumped_hashes, output_file, emit_match_logs=False):
            return 1, 1

    cracked = tmp_path / "cracked.txt"
    dumped = tmp_path / "dump.ntds"
    cracked.write_text("user:pass\n", encoding="utf-8")
    dumped.write_text("user:x:x:x:x:x:x\n", encoding="utf-8")

    harness = Harness()
    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        harness.generate_password_list_from_hashes(
            {
                "hashes": str(cracked),
                "dumps": str(dumped),
                "filename": "pw_output",
            },
            str(tmp_path),
            lambda name, extension="txt": name,
        )
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Getting cracked hashes" in transcript


def test_compare_hash_from_dump_routes_hash_runtime_output_to_transcript_when_stdout_is_suppressed(
    tmp_path,
    capsys,
):
    cracked = tmp_path / "cracked.txt"
    dumped = tmp_path / "dump.ntds"
    output_file = tmp_path / "pw_output.txt"

    cracked.write_text(
        "0123456789abcdef0123456789abcdef:Winter2024!\n"
        "malformed-line-without-separator\n",
        encoding="utf-8",
    )
    dumped.write_text(
        "EXAMPLE\\alice:1000:LMHASH:0123456789abcdef0123456789abcdef:::Enabled\n"
        "broken:line\n",
        encoding="utf-8",
    )

    harness = PasswordModule()
    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        matches_found, enabled_users = harness.compare_hash_from_dump(
            str(cracked),
            str(dumped),
            str(output_file),
            emit_match_logs=True,
        )
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert matches_found == 1
    assert enabled_users == 1
    assert "Skipping malformed line in" in transcript
    assert "Loaded 1 cracked hashes" in transcript
    assert "Match found: alice:Winter2024!" in transcript
    assert "Skipped 1 malformed dump lines" in transcript
