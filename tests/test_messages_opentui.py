from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.shared.decorators import CustomDecorators
from utils.shared.loader import Loader


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


def test_loader_records_progress_in_transcript_when_stdout_is_suppressed(capsys):
    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        loader = Loader(desc="Processing Vulnerabilities", end="Processing Complete")
        loader.start()
        loader.stop()
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Processing Vulnerabilities" in transcript
    assert "Processing Complete" in transcript


def test_custom_decorators_runtime_messages_follow_output_capture(capsys):
    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        CustomDecorators.total_time = 65
        CustomDecorators.last_execution_time = 5
        CustomDecorators.print_total_time("Analysis Completed in Approximately:")
        CustomDecorators.print_last_execution_time("Execution time:")
    finally:
        DisplayHandler.set_stdout_suppressed(False)
        CustomDecorators.reset_total_time()

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Analysis Completed in Approximately:" in transcript
    assert "1 minute and 5 seconds." in transcript
    assert "Execution time:" in transcript
    assert "5 seconds" in transcript
