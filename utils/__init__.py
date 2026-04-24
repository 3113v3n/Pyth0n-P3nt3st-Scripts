"""Lazy exports for top-level utility modules."""

from importlib import import_module


_EXPORTS = {
    "HashUtil": (".internal.hash_util", "HashUtil"),
    "NetExec": (".internal.netexec", "NetExec"),
    "CredentialsUtil": (".internal.test_creds", "CredentialsUtil"),
    "MobileCommands": (".mobile.mobile_commands", "MobileCommands"),
    "FilterVulnerabilities": (".vulnerability.filter_vulnerabilities", "FilterVulnerabilities"),
    "Bcolors": (".shared.colors", "Bcolors"),
    "Commands": (".shared.commands", "Commands"),
    "Config": (".shared.config", "Config"),
    "ProgressBar": (".shared.progress_bar", "ProgressBar"),
    "Validator": (".shared.validators", "Validator"),
    "Loader": (".shared.loader", "Loader"),
    "CustomDecorators": (".shared.decorators", "CustomDecorators"),
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attr_name = _EXPORTS[name]
    module = import_module(f"{__name__}{module_name}")
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
