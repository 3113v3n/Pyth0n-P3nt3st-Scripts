import sys
from subprocess import CompletedProcess

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.shared.commands import Commands


def test_stream_command_routes_output_to_transcript_when_stdout_is_suppressed(capsys):
    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = Commands.stream_command(
            [
                sys.executable,
                "-c",
                "print('alpha')\nprint('beta')",
            ],
            prefix="[tool] ",
        )
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result.returncode == 0
    assert "alpha" in result.stdout
    assert "beta" in result.stdout
    assert "[tool] alpha" in transcript
    assert "[tool] beta" in transcript


def test_run_git_cmd_routes_status_messages_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    def _fake_run(*args, **kwargs):
        return CompletedProcess(args[0], 0)

    monkeypatch.setattr("utils.shared.commands.subprocess.run", _fake_run)

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = Commands.run_git_cmd(["git", "status"])
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result is True
    assert "Running command:" in transcript
    assert "git status" in transcript
    assert "Command completed successfully." in transcript
