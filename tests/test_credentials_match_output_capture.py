from pathlib import Path

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.internal import credentials_match


def test_credentials_match_main_routes_success_message_to_transcript_when_stdout_is_suppressed(
    tmp_path,
    monkeypatch,
    capsys,
):
    usernames = tmp_path / "users.txt"
    creds = tmp_path / "creds.txt"
    usernames.write_text("alice\n", encoding="utf-8")
    creds.write_text("alice Winter2024!\n", encoding="utf-8")

    responses = iter([str(usernames), str(creds)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt='': next(responses))

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        credentials_match.main()
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Processing complete. Results written to matched.txt" in transcript
    assert (tmp_path / "matched.txt").read_text(encoding="utf-8") == "alice:Winter2024!\n"


def test_credentials_match_main_routes_file_error_to_transcript_when_stdout_is_suppressed(
    tmp_path,
    monkeypatch,
    capsys,
):
    missing = tmp_path / "missing.txt"
    responses = iter([str(missing), str(missing)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt='': next(responses))

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        credentials_match.main()
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Error: One of the input files was not found" in transcript
