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

### Refactor Improvements
- Navigation guidance is now shown above interactive prompts with concise shortcut help:
  - `back` for previous step, `main` for Menu 1, `Up/Down` for input history, `Ctrl+C` for graceful exit.
- Interactive prompt handling now sanitizes terminal escape sequences to avoid noisy input artifacts such as `^[[A` appearing as invalid input.
- Navigation hint rendering is now viewport-aware:
  - the hint is shown once while still visible on-screen,
  - it is re-shown only after enough output likely pushed it off-screen or after an explicit terminal clear.
- Base64 analysis now applies stricter relevance checks:
  - skips common media/data-URI payloads (for example SVG/image/font embedded blobs),
  - retains decoded payloads that are likely security-relevant (tokens, secrets, auth material, suspicious URLs/keys).
- Reporting output wrappers were enhanced for readability:
  - consistent section headers,
  - wrapped long lines,
  - indented key/value blocks,
  - structured finding sections for easier review of large outputs.
