"""Shared interactive menu navigation primitives."""

from __future__ import annotations


BACK_COMMANDS = {"b", "back"}
MAIN_MENU_COMMANDS = {"m", "main", "main menu", "main-menu", "menu", "home"}


class MenuNavigation(Exception):
    """Base exception used to unwind nested menu flows."""


class BackToPreviousMenu(MenuNavigation):
    """Raised when the user requests to go back one menu level."""


class BackToMainMenu(MenuNavigation):
    """Raised when the user requests to jump back to the main menu."""


def check_navigation_command(value: str) -> None:
    """Raise menu navigation exceptions for recognized command tokens."""
    token = str(value).strip().lower()
    if token in BACK_COMMANDS:
        raise BackToPreviousMenu()
    if token in MAIN_MENU_COMMANDS:
        raise BackToMainMenu()
