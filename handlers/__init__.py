"""Lazy exports for handler classes."""

from importlib import import_module


_EXPORTS = {
    "FileHandler": (".file_handler", "FileHandler"),
    "NetworkHandler": (".network_handler", "NetworkHandler"),
    "PackageHandler": (".package_handler", "PackageHandler"),
    "UserHandler": (".user_handler", "UserHandler"),
    "DisplayHandler": (".messages", "DisplayHandler"),
    "ScreenHandler": (".screen", "ScreenHandler"),
    "HelpHandler": (".helper_handler", "HelpHandler"),
    "InteractionHandler": (".interaction", "InteractionHandler"),
    "CustomArgumentParser": (".custom_parser", "CustomArgumentParser"),
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
