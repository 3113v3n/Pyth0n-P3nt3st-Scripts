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
- Mobile nuclei report rendering now uses aligned inline columns with condensed project-relative extraction paths and hanging-wrap continuation for long file paths.
- Mobile integrity findings/controls now render as inline, column-aligned records (instead of section blocks) for easier scanning and grep-friendly output.
- Base64 finding output now omits legacy START/END wrappers and keeps long decoded tokens (for example JWT-like strings) wrapped consistently for readability.
- API-key checklist output now omits legacy star-banner header/footer wrappers.
- Mobile extraction now reuses cached decompilation folders in `.tmp/mobile-extraction` when available, skipping redundant decompile work on repeated scans.
- Duplicate extraction folders for the same app are now pruned automatically, keeping a single active cache directory per app fingerprint.

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
- Base64 report ingestion for AI/mobile findings parsing now supports both legacy START/END blocks and the newer section-header-only format.
- Added a mandatory secure-coding gate:
  - new `SECURITY.md` policy/checklist,
  - tracked `.githooks/pre-commit` gate for local commits,
  - `scripts/security_gate.py` validator for staged/PR diffs,
  - CI workflow `.github/workflows/security-gate.yml` enforcing the same checks on push/PR.
