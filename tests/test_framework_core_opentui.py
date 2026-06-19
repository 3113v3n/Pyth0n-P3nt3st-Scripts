from handlers.framework_core_mixin import FrameworkCoreMixin


class _PackageStub:
    def __init__(self):
        self.is_supported_os = None
        self.operating_system = "linux"

    def _check_is_supported(self):
        return True

    def get_missing_packages(self, user_test_domain):
        return []


class _CoreHarness(FrameworkCoreMixin):
    def __init__(self):
        self.use_ai = True
        self.ai = None
        self.classes = {"package": _PackageStub(), "domains": {}}
        self.info_messages = []
        self.warning_messages = []

    def _attach_ai_to_domains(self):
        return None

    def print_info_message(self, message, **kwargs):
        self.info_messages.append((message, kwargs))

    def print_warning_message(self, message, **kwargs):
        self.warning_messages.append((message, kwargs))


class _AIDisabledStub:
    def __init__(self):
        self.startup_notice = (
            "warning",
            "[AI] ANTHROPIC_API_KEY environment variable not set. AI features are disabled.",
        )
        self.enabled = False


def test_check_packages_uses_info_message_for_interactive_status():
    harness = _CoreHarness()

    result = harness.check_packages("mobile")

    assert result is True
    assert harness.info_messages[0][0] == "Checking for required packages..."


def test_ensure_ai_ready_routes_startup_notice_through_display_handler(monkeypatch):
    import handlers.framework_core_mixin as core_module

    monkeypatch.setattr(core_module, "PentestAI", _AIDisabledStub)
    harness = _CoreHarness()

    harness.ensure_ai_ready()

    assert harness.ai is not None
    assert harness.warning_messages[0][0].startswith("[AI] ANTHROPIC_API_KEY")
    assert harness.ai.startup_notice is None
