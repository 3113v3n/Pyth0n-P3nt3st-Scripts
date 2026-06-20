from subprocess import CompletedProcess

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.internal.netexec import NetExec


def test_gen_relay_list_routes_paths_to_transcript_when_stdout_is_suppressed(capsys):
    harness = NetExec()
    harness.run_os_commands = lambda command: CompletedProcess(command, 0, stdout="", stderr="")

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = harness.gen_relay_list("input.txt", "output.txt")
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result == ["netexec", "smb", "input.txt", "--gen-relay-list", "output.txt"] or transcript
    assert "input.txt" in transcript
    assert "output.txt" in transcript
