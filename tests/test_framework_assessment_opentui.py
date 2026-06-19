from handlers.framework_assessment_mixin import FrameworkAssessmentMixin
from handlers.navigation import BackToPreviousMenu
from utils.shared.commands import StrictModeViolation


class _AssessmentHarness(FrameworkAssessmentMixin):
    def __init__(self):
        self.auto_relax_on_strict = False
        self.info_messages = []
        self.warning_messages = []
        self.prompt_calls = []
        self.prompt_result: object = "yes"
        self.classes = {}

    def print_info_message(self, message, **kwargs):
        self.info_messages.append((message, kwargs))

    def print_warning_message(self, message, **kwargs):
        self.warning_messages.append((message, kwargs))

    def prompt_for_choice(self, **kwargs):
        self.prompt_calls.append(kwargs)
        if isinstance(self.prompt_result, Exception):
            raise self.prompt_result
        return self.prompt_result


class _AssessmentUserStub:
    def __init__(self):
        self.prompt_calls = []
        self.prompt_result = "yes"

    def prompt_for_choice(self, **kwargs):
        self.prompt_calls.append(kwargs)
        if isinstance(self.prompt_result, Exception):
            raise self.prompt_result
        return self.prompt_result


def test_should_temporarily_relax_returns_true_when_autorelax_enabled():
    harness = _AssessmentHarness()
    harness.auto_relax_on_strict = True

    result = harness._should_temporarily_relax(
        "mobile assessment",
        StrictModeViolation("blocked"),
    )

    assert result is True
    assert harness.prompt_calls == []


def test_should_temporarily_relax_returns_false_for_non_interactive(monkeypatch):
    harness = _AssessmentHarness()
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: False})())

    result = harness._should_temporarily_relax(
        "external assessment",
        StrictModeViolation("blocked"),
    )

    assert result is False
    assert harness.prompt_calls == []
    assert any("non-interactive" in message for message, _ in harness.warning_messages)


def test_should_temporarily_relax_uses_prompt_for_choice_when_interactive(monkeypatch):
    harness = _AssessmentHarness()
    harness.prompt_result = "no"
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    result = harness._should_temporarily_relax(
        "vulnerability analysis",
        StrictModeViolation("blocked by strict mode"),
    )

    assert result is False
    assert len(harness.prompt_calls) == 1
    prompt_call = harness.prompt_calls[0]
    assert prompt_call["title"] == "Strict Mode"
    assert "temporary relaxed mode" in prompt_call["prompt"].lower()
    assert prompt_call["default"] == "yes"


def test_should_temporarily_relax_returns_false_when_prompt_is_cancelled(monkeypatch):
    harness = _AssessmentHarness()
    harness.prompt_result = BackToPreviousMenu()
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    result = harness._should_temporarily_relax(
        "internal assessment",
        StrictModeViolation("blocked by strict mode"),
    )

    assert result is False


def test_should_temporarily_relax_accepts_default_yes_when_prompt_returns_yes(monkeypatch):
    harness = _AssessmentHarness()
    harness.prompt_result = "yes"
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    result = harness._should_temporarily_relax(
        "internal assessment",
        StrictModeViolation("blocked by strict mode"),
    )

    assert result is True


def test_should_temporarily_relax_uses_user_handler_prompt_when_framework_lacks_prompt(monkeypatch):
    class _AssessmentHarnessNoPrompt(FrameworkAssessmentMixin):
        def __init__(self):
            self.auto_relax_on_strict = False
            self.info_messages = []
            self.warning_messages = []
            self.classes = {"user": _AssessmentUserStub()}

        def print_info_message(self, message, **kwargs):
            self.info_messages.append((message, kwargs))

        def print_warning_message(self, message, **kwargs):
            self.warning_messages.append((message, kwargs))

    harness = _AssessmentHarnessNoPrompt()
    harness.classes["user"].prompt_result = "no"
    monkeypatch.setattr("sys.stdin", type("_Stdin", (), {"isatty": lambda self: True})())

    result = harness._should_temporarily_relax(
        "external assessment",
        StrictModeViolation("blocked by strict mode"),
    )

    assert result is False
    assert harness.classes["user"].prompt_calls[0]["title"] == "Strict Mode"
