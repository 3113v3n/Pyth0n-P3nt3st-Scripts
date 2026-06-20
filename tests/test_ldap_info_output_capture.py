import importlib
import sys
import types

from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler


def _install_fake_ldap3(monkeypatch):
    ldap3_module = types.ModuleType("ldap3")
    conv_module = types.ModuleType("ldap3.utils.conv")
    utils_module = types.ModuleType("ldap3.utils")

    class LDAPException(Exception):
        pass

    class Server:
        def __init__(self, server_ip, get_info=None, port=389, use_ssl=False):
            self.server_ip = server_ip
            self.info = f"server-info:{server_ip}:{port}:{use_ssl}"

    class Connection:
        def __init__(self, server):
            self.server = server
            self.entries = ["entry-one", "entry-two"]
            self.search_calls = []

        def bind(self):
            return True

        def unbind(self):
            return True

        def search(self, **kwargs):
            self.search_calls.append(kwargs)
            return True

    conv_module.escape_filter_chars = lambda value: f"escaped:{value}"
    utils_module.conv = conv_module
    ldap3_module.Server = Server
    ldap3_module.Connection = Connection
    ldap3_module.ALL = object()
    ldap3_module.core = types.SimpleNamespace(exceptions=types.SimpleNamespace(LDAPException=LDAPException))
    ldap3_module.utils = utils_module

    monkeypatch.setitem(sys.modules, "ldap3", ldap3_module)
    monkeypatch.setitem(sys.modules, "ldap3.utils", utils_module)
    monkeypatch.setitem(sys.modules, "ldap3.utils.conv", conv_module)
    sys.modules.pop("utils.internal.ldap_info", None)
    return importlib.import_module("utils.internal.ldap_info")


def test_fetch_ldap_server_info_routes_messages_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    ldap_info = _install_fake_ldap3(monkeypatch)

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        ldap_info.fetch_ldap_server_info("10.0.0.5", 389)
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "LDAP server information:" in transcript
    assert "server-info:10.0.0.5:389:False" in transcript
    assert "LDAP connection closed." in transcript


def test_fetch_ad_objects_routes_entries_to_transcript_when_stdout_is_suppressed(monkeypatch, capsys):
    ldap_info = _install_fake_ldap3(monkeypatch)

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        result = ldap_info.fetch_ad_objects("10.0.0.5", "DC=corp,DC=local", "(objectClass=user)")
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert result == ["entry-one", "entry-two"]
    assert "Active Directory objects found: 2" in transcript
    assert "entry-one" in transcript
    assert "entry-two" in transcript
    assert "LDAP connection closed." in transcript
