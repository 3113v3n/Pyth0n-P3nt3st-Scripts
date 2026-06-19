from handlers.helper_handler import HelpHandler
from handlers.navigation import BackToMainMenu
from handlers.user_handler import UserHandler


class _CommandStub:
    def clear_screen(self):
        return None


def test_set_domain_variables_dispatches_to_domain_handler(monkeypatch):
    handler = UserHandler(HelpHandler(), _CommandStub())

    monkeypatch.setattr(handler, "update_output_directory", lambda domain: None)
    monkeypatch.setattr(handler, "mobile_ui_handler", lambda: {"module": "mobile", "filename": "app.apk"})

    result = handler.set_domain_variables("mobile")

    assert result == {"module": "mobile", "filename": "app.apk"}
    assert handler.domain_variables == result


def test_help_me_uses_text_viewer_and_returns_to_main_menu(monkeypatch):
    handler = UserHandler(HelpHandler(), _CommandStub())
    captured = {}

    monkeypatch.setattr(
        handler,
        "show_text_viewer",
        lambda **kwargs: captured.update(kwargs),
    )

    try:
        handler.help_me()
    except BackToMainMenu:
        pass
    else:
        raise AssertionError("help_me should return to the main menu")

    assert captured["title"] == "Help Center"
    assert "Custom Help Menu" in captured["body"]
    assert "CLI reference" in captured["prompt"]
