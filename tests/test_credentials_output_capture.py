import subprocess
from types import SimpleNamespace

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.internal.test_creds import CredentialsUtil


def test_split_pass_file_routes_missing_file_message_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    harness = CredentialsUtil()
    harness.creds_file = "/tmp/does-not-exist-creds.txt"
    monkeypatch.setattr(
        "utils.internal.test_creds.parse_credentials_from_output",
        lambda path: (_ for _ in ()).throw(FileNotFoundError(path)),
    )

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = harness.split_pass_file()
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result == {}
    assert "Credentials file not found" in transcript


def test_test_credentials_routes_start_and_empty_list_messages_to_transcript_when_stdout_is_suppressed(
    tmp_path,
    monkeypatch,
    capsys,
):
    harness = CredentialsUtil()
    monkeypatch.setattr(harness, "split_pass_file", lambda: {})

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        harness.test_credentials(
            target="10.0.0.1",
            domain="example.local",
            output_file=str(tmp_path / "success.txt"),
            passlist=str(tmp_path / "creds.txt"),
            save_dir=str(tmp_path),
        )
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Starting credential test against 10.0.0.1" in transcript
    assert "No valid credentials found to test." in transcript


def test_run_nxc_routes_timeout_output_to_transcript_when_stdout_is_suppressed(tmp_path, capsys):
    harness = CredentialsUtil()
    harness.target = "10.0.0.1"
    harness.output_file = str(tmp_path / "success.txt")
    harness._nxc_env = harness._build_nxc_env(str(tmp_path))

    timeout_error = subprocess.TimeoutExpired(
        cmd=["nxc", "smb", "10.0.0.1"],
        timeout=harness.NXC_COMMAND_TIMEOUT_SECONDS,
        output="line one\nline two\n",
    )
    harness.run_command = SimpleNamespace(
        run_nxc_command=lambda *args, **kwargs: (_ for _ in ()).throw(timeout_error)
    )

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        harness.run_nxc("alice", "Winter2024!", "example.local", str(tmp_path))
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "line one" in transcript
    assert "line two" in transcript
    assert "nxc timed out after" in transcript
