from types import SimpleNamespace

import pytest

from handlers.file_handler import FileHandler
from handlers.interaction import InteractionHandler
from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler


class _ValidatorStub:
    @staticmethod
    def check_folder_exists(_path):
        return True


class _FileHandlerStub:
    @staticmethod
    def find_files(_path):
        return None

    @staticmethod
    def _get_file_collections():
        return {"csv": [], "excel": []}

    @staticmethod
    def _filter_files_by_extension(_collection, extension="both"):
        assert extension == "both"
        return ["scan1.csv", "scan2.xlsx"]


def test_handle_va_arguments_routes_status_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    handler = InteractionHandler()
    monkeypatch.setattr(handler, "validator", _ValidatorStub())
    monkeypatch.setattr(handler, "filehandler", _FileHandlerStub())
    args = SimpleNamespace(
        scanner="nessus",
        path="test-data/nessus",
        output="report.xlsx",
        credentialed_check=True,
    )

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = handler.handle_va_arguments(args, "va")
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result["scanner"] == "nessus"
    assert result["scan_files"] == ["scan1.csv", "scan2.xlsx"]
    assert "Running Nessus Vulnerability Analysis" in transcript


def test_read_excel_file_routes_errors_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    def _boom(*args, **kwargs):
        raise ValueError("bad workbook")

    monkeypatch.setattr("handlers.file_handler.pandas.read_excel", _boom)

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        with pytest.raises(ValueError, match="bad workbook"):
            FileHandler.read_excel_file("broken.xlsx")
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Error reading excel file" in transcript
    assert "bad workbook" in transcript
