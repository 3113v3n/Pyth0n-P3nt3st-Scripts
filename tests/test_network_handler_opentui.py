from handlers.network_handler import NetworkHandler
from utils.shared.progress_bar import ProgressBar


class _NetworkHarness(NetworkHandler):
    def __init__(self):
        super().__init__()
        self.scan_calls = []
        self.errors = []
        self.progress_bar = ProgressBar()
        self.progress_bar.configure(mode="scan", subnet="192.168.1.0/24", interface="eth0")

    def scan_network(self, mode: str, output_file: str):
        self.scan_calls.append((mode, output_file))
        self.progress_bar.live_hosts.add("192.168.1.10")
        self.progress_bar.mark_finished(interrupted=False)

    def print_error_message(self, message: str = "Error", **kwargs):
        self.errors.append((message, kwargs))


def test_get_live_ips_uses_tui_progress_viewer(monkeypatch):
    import handlers.screen as screen_module

    harness = _NetworkHarness()
    harness.mode = "resume"

    captured = {}

    def fake_show_progress_viewer(**kwargs):
        captured.update(kwargs)
        kwargs["worker"]()
        return kwargs["snapshot_getter"]()

    monkeypatch.setattr(screen_module.ScreenHandler, "show_progress_viewer", staticmethod(fake_show_progress_viewer))

    result = harness.get_live_ips("resume_hosts.csv")

    assert result == 1
    assert harness.scan_calls == [("resume", "resume_hosts.csv")]
    assert captured["title"] == "Internal Network Progress"
    assert captured["cancel"] == harness.shutdown_event.set
