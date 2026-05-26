# Changelog

All notable project changes should be recorded in this file.

## 2026-05-26

### Added
- Global interactive navigation commands:
  - `back`/`b` to return to previous menu step.
  - `main`/`m` (`menu`, `home`) to return directly to Main Menu.
- Shared menu navigation module at `handlers/navigation.py`.
- Navigation hint display for interactive module wizards.

### Changed
- Converted interactive module flows (`mobile`, `internal`, `external`, `va`, `password`) into step-based wizards that preserve selected values when going back, unless the user explicitly returns to Main Menu.
- Updated runtime loop to handle Main Menu navigation without exiting the program.
- Updated numeric/file selection menus to accept navigation commands alongside numeric input.
