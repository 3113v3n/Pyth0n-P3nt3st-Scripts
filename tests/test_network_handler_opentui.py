from handlers.network_handler import NetworkHandler
from utils.shared.progress_bar import ProgressBar


class _NetworkHarness(NetworkHandler):
    def __init__(self):
        super().__init__()
        self.scan_calls = []
        self.errors = []
        self.progress_bar = ProgressBar()
        self.progress_bar.configure(mode="scan", subnet="192.168.1.0/24", interface="eth0")
        self.scan_complete = False

    def scan_network(self, mode: str, output_file: str):
        self.scan_calls.append((mode, output_file))
        self.progress_bar.live_hosts.add("192.168.1.10")
        self.progress_bar.mark_finished(interrupted=False)
        self.scan_complete = True

    def print_error_message(self, message: str = "Error", **kwargs):
        self.errors.append((message, kwargs))


class _ThreadSafeSignalHarness(NetworkHandler):
    def __init__(self):
        super().__init__()
        self.progress_bar = ProgressBar()
        self.progress_bar.configure(mode="scan", subnet="192.168.1.0/30", interface="eth0")
        self.interface = "eth0"
        self.subnet = "192.168.1.0/30"
        self.hosts = 2
        self.mode = "scan"
        self.saved = []

    @staticmethod
    def get_interface_ip(interface: str):
        return "192.168.1.5"

    def _initialize_scan_session(self, mode: str, output_file: str) -> None:
        self.current_scan_session = None

    def generate_ip_in_batches(self, batch_size: int = 256):
        self.progress_bar.set_total_hosts(2)
        yield ["192.168.1.1", "192.168.1.2"]

    def start_async_ping(self, ip: str):
        return ip.endswith("1")

    def save_to_csv(self, filename: str, ip: str):
        self.saved.append((filename, ip))

    def monitor_interface(self):
        return None

    def print_error_message(self, message: str = "Error", **kwargs):
        raise AssertionError(f"unexpected error: {message} {kwargs}")


def test_get_live_ips_uses_tui_progress_viewer(monkeypatch):
    import handlers.opentui_menu as opentui_menu_module
    import handlers.screen as screen_module

    harness = _NetworkHarness()
    harness.mode = "resume"

    captured = {}

    def fake_show_progress_viewer(**kwargs):
        captured.update(kwargs)
        kwargs["worker"]()
        return kwargs["snapshot_getter"]()

    monkeypatch.setattr(opentui_menu_module, "opentui_menu_enabled", lambda: True)
    monkeypatch.setattr(screen_module.ScreenHandler, "show_progress_viewer", staticmethod(fake_show_progress_viewer))

    result = harness.get_live_ips("resume_hosts.csv")

    assert result == 1
    assert harness.scan_calls == [("resume", "resume_hosts.csv")]
    assert captured["title"] == "Internal Network Progress"
    assert captured["cancel"] == harness.shutdown_event.set


def test_get_live_ips_falls_back_to_direct_scan_when_opentui_disabled(monkeypatch):
    import handlers.opentui_menu as opentui_menu_module

    harness = _NetworkHarness()
    harness.mode = "scan"
    monkeypatch.setattr(opentui_menu_module, "opentui_menu_enabled", lambda: False)

    result = harness.get_live_ips("scan.csv")

    assert result == 1
    assert harness.scan_calls == [("scan", "scan.csv")]


def test_scan_network_skips_signal_registration_in_worker_thread():
    import threading

    harness = _ThreadSafeSignalHarness()
    errors = []

    worker = threading.Thread(
        target=lambda: _run_scan_capture_error(harness, errors),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=5)

    assert worker.is_alive() is False
    assert errors == []
    assert harness.scan_complete is True
    assert len(harness.progress_bar.live_hosts) == 1
    assert len(harness.progress_bar.unresponsive_hosts) == 1


def _run_scan_capture_error(harness, errors):
    try:
        harness.scan_network("scan", "scan.csv")
    except Exception as error:  # pragma: no cover - explicit assertion captures failures
        errors.append(str(error))
