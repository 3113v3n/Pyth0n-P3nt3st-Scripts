"""Lazy exports for assessment domain classes."""

from importlib import import_module


_EXPORTS = {
    "ExternalAssessment": (".external_module", "ExternalAssessment"),
    "InternalAssessment": (".internal_module", "InternalAssessment"),
    "MobileAssessment": (".mobile_module", "MobileAssessment"),
    "VulnerabilityAnalysis": (".vulnerability_module", "VulnerabilityAnalysis"),
    "PasswordModule": (".password_module", "PasswordModule"),
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
