from handlers.framework_runtime_mixin import FrameworkRuntimeMixin
from handlers.navigation import BackToMainMenu
from handlers.opentui_menu import OpenTUIMenuRequired


class _UserStub:
    def __init__(self):
        self.prompt_calls = []
        self.prompt_result = "yes"
        self.domain_result = OpenTUIMenuRequired("OpenTUI missing")
        self.viewer_calls = []

    def get_user_domain(self):
        if isinstance(self.domain_result, Exception):
            raise self.domain_result
        return self.domain_result

    def prompt_for_choice(self, **kwargs):
        self.prompt_calls.append(kwargs)
        if isinstance(self.prompt_result, Exception):
            raise self.prompt_result
        return self.prompt_result

    def show_text_viewer(self, **kwargs):
        self.viewer_calls.append(kwargs)


class _CommandStub:
    def __init__(self):
        self.cleaned = False

    def clear_screen(self):
        return None

    def cleanup_runtime_tmp(self):
        self.cleaned = True


class _RuntimeHarness(FrameworkRuntimeMixin):
    def __init__(self):
        self.exit_menu = False
        self.classes = {
            "user": _UserStub(),
            "command": _CommandStub(),
        }
        self.errors = []
        self.package_checks = []
        self.ai_ready_calls = 0
        self.processed_domains = []

    def reset_class_states(self):
        return None

    def check_packages(self, test_domain):
        self.package_checks.append(test_domain)
        return True

    def ensure_ai_ready(self):
        self.ai_ready_calls += 1
        return None

    def process_domain(self, test_domain, user_data=None):
        self.processed_domains.append((test_domain, user_data))
        return None

    def print_error_message(self, message=None, exception_error=None, **kwargs):
        self.errors.append((message, str(exception_error) if exception_error else None))

    def print_info_message(self, *args, **kwargs):
        return None

    def print_warning_message(self, *args, **kwargs):
        return None


def test_run_program_exits_when_opentui_is_required(monkeypatch):
    harness = _RuntimeHarness()
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    harness.run_program()

    assert harness.exit_menu is True
    assert harness.classes["command"].cleaned is True
    assert harness.errors[0][0] == "OpenTUI is required for interactive mode"


def test_get_user_input_uses_tui_prompt_when_available():
    harness = _RuntimeHarness()
    harness.classes["user"].prompt_result = "no"

    result = harness.get_user_input_()

    assert result == "no"
    assert harness.classes["user"].prompt_calls[0]["title"] == "Exit Program"


def test_get_user_input_returns_no_when_tui_exit_prompt_jumps_to_main_menu():
    harness = _RuntimeHarness()
    harness.classes["user"].prompt_result = BackToMainMenu()

    assert harness.get_user_input_() == "n"


def test_run_program_exits_cleanly_when_exit_is_selected(monkeypatch):
    harness = _RuntimeHarness()
    harness.classes["user"].domain_result = "exit"
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    harness.run_program()

    assert harness.exit_menu is True
    assert harness.package_checks == []
    assert harness.ai_ready_calls == 0
    assert harness.processed_domains == []


def test_space_recovery_hint_uses_tui_viewer_when_available(monkeypatch):
    harness = _RuntimeHarness()
    harness.classes["user"].viewer_calls = []

    monkeypatch.setattr(harness, "_can_render_interactive_tui", lambda: True)
    monkeypatch.setattr(
        harness,
        "_collect_space_recovery_paths",
        lambda module, run_started_at: ["output_directory/Mobile/report.txt"],
    )
    harness._print_space_recovery_hint("mobile", 0.0)

    assert harness.classes["user"].viewer_calls[0]["title"] == "Space Recovery"
    assert "output_directory/Mobile/report.txt" in harness.classes["user"].viewer_calls[0]["body"]


def test_show_module_output_transcript_uses_tui_viewer(monkeypatch):
    import handlers.screen as screen_module

    harness = _RuntimeHarness()
    monkeypatch.setattr(harness, "_can_render_interactive_tui", lambda: True)
    monkeypatch.setattr(
        screen_module.ScreenHandler,
        "consume_output_transcript",
        classmethod(lambda cls: "Final summary\nSaved report: output_directory/Mobile/report.txt"),
    )

    harness._show_module_output_transcript("mobile")

    assert harness.classes["user"].viewer_calls[0]["title"] == "Mobile Output"
    assert "Saved report" in harness.classes["user"].viewer_calls[0]["body"]
