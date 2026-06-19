"""Lazy exports for shared utility classes.

This keeps import-time dependencies minimal so optional modules do not fail
startup before they are actually needed.
"""

from importlib import import_module


_EXPORTS = {
    "AssessmentError": (".errors", "AssessmentError"),
    "Bcolors": (".colors", "Bcolors"),
    "Commands": (".commands", "Commands"),
    "Config": (".config", "Config"),
    "DomainError": (".errors", "DomainError"),
    "ProgressBar": (".progress_bar", "ProgressBar"),
    "MissingRequiredFileError": (".errors", "MissingRequiredFileError"),
    "ModuleArgumentError": (".errors", "ModuleArgumentError"),
    "PentestFrameworkError": (".errors", "PentestFrameworkError"),
    "Validator": (".validators", "Validator"),
    "VulnerabilityAnalysisError": (".errors", "VulnerabilityAnalysisError"),
    "Loader": (".loader", "Loader"),
    "VAConfigs": (".configurations.va_configs", "VAConfigs"),
    "CustomDecorators": (".decorators", "CustomDecorators"),
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
