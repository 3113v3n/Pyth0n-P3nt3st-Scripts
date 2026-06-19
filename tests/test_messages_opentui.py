from handlers.messages import DisplayHandler


def test_display_handler_can_suppress_stdout(capsys):
    DisplayHandler.set_stdout_suppressed(True)
    try:
        DisplayHandler.print_info_message("Checking for required packages...")
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    assert captured.out == ""


def test_display_handler_prints_when_suppression_disabled(capsys):
    DisplayHandler.set_stdout_suppressed(False)
    DisplayHandler.print_info_message("Checking for required packages...")

    captured = capsys.readouterr()
    assert "Checking for required packages" in captured.out
