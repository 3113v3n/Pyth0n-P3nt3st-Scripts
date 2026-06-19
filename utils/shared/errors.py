"""Shared exception hierarchy for user-facing validation and assessment failures."""

from __future__ import annotations


class PentestFrameworkError(Exception):
    """Base class for framework-specific failures."""


class ModuleArgumentError(PentestFrameworkError, ValueError):
    """Raised when CLI or interactive module arguments are invalid."""


class MissingRequiredFileError(ModuleArgumentError):
    """Raised when an expected input file is missing or invalid."""


class AssessmentError(PentestFrameworkError, RuntimeError):
    """Base class for module execution failures."""


class DomainError(PentestFrameworkError):
    """Raised when a domain-specific UI flow fails or returns invalid data."""


class VulnerabilityAnalysisError(AssessmentError):
    """Raised when vulnerability analysis cannot proceed or complete."""
