from subprocess import CompletedProcess

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.external import domain_recon


def test_shell_command_routes_debug_and_failure_messages_to_transcript_when_stdout_is_suppressed(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(domain_recon, "which_tool", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(
        domain_recon._COMMANDS,
        "stream_command",
        lambda command, prefix=None: CompletedProcess(command, 1, stdout="failure output", stderr=""),
    )

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = domain_recon.shell_command(["subfinder", "-d", "example.com"], "subfinder", debug=True)
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result == []
    assert "Executing: /usr/bin/subfinder -d example.com" in transcript
    assert "[!] subfinder failed with exit code 1" in transcript


def test_run_dnsx_routes_failure_message_to_transcript_when_stdout_is_suppressed(tmp_path, monkeypatch, capsys):
    input_file = tmp_path / "subs.txt"
    input_file.write_text("api.example.com\n", encoding="utf-8")
    output_file = tmp_path / "resolved.txt"
    output_file.write_text("stale\n", encoding="utf-8")

    monkeypatch.setattr(domain_recon, "available_name", lambda name: "/usr/bin/dnsx")
    monkeypatch.setattr(
        domain_recon._COMMANDS,
        "stream_command",
        lambda cmd, output_file=None, prefix=None: CompletedProcess(cmd, 2, stdout="", stderr=""),
    )

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        domain_recon.DomainRecon.run_dnsx(input_file, output_file)
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert output_file.exists() is False
    assert "[!] dnsx failed with exit code 2" in transcript
