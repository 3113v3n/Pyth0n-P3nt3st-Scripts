# Changelog

All notable project changes should be recorded in this file.

## 2026-06-19

### Added
- Added OpenTUI-powered selectors, viewers, and prompt flows across the interactive framework so workflow selection, helper views, text entry, and multiselect screens stay inside a richer terminal UI.
- Added an OpenTUI internal network progress display that shows responsive hosts, unresponsive hosts, progress, scan metadata, and graceful-stop guidance for both scan and resume modes.
- Added interactive output transcript capture so final module summaries can be surfaced back to the operator in TUI viewers instead of leaking as native terminal output.
- Added focused regression coverage for OpenTUI runtime flows, progress handling, message suppression, and internal network display behavior.

### Changed
- Reworked interactive input rendering so the prompt marker is a true prefix and typed content appears after it with an inline cursor indicator.
- Updated internal scan/resume execution to remove the legacy curses/tqdm host display path from interactive mode and route progress through OpenTUI instead.
- Updated interactive runtime/message handling to suppress pre-TUI stdout leaks such as dependency checks and AI startup warnings while still capturing those messages for final TUI presentation.
- Improved runtime output handling so space-recovery guidance and module summaries use TUI viewers when OpenTUI is available, while CLI argument mode remains compatible with plain terminal output.
- Split shared handlers and helper logic into smaller modules to support the new TUI-driven workflow structure, package/runtime helpers, and expanded validation paths.

### Validation
- Verified targeted OpenTUI/runtime regression coverage with focused pytest runs for menu rendering, runtime flow, progress handling, and message suppression.
- Verified repository test coverage with the full suite (`140 passed`).
- Verified bundled test-data execution paths for vulnerability analysis (Nessus and Rapid7), password list generation, and mobile APK analysis, confirming output artifacts were produced successfully.

## 2026-06-15

### Added
- Added a VA commit runbook covering pre-commit review, focused staging, changelog updates, verification, and push steps.
- Added a Nessus executive summary sheet with plugin-level rollups for affected IP counts, grouped plugin IDs, and finding rows.
- Added Nessus `CVSS Vector` output normalization so reports include a stable vector column even when source exports use CVSS variant headers.
- Added Rapid7 support for both full exports and slimmer report exports through required core columns plus optional export fields.
- Added Rapid7 VA categories for remote code execution, RDP misconfiguration, information disclosure, and reboot findings.
- Added CLI and interactive VA credentialed/uncredentialed selection, defaulting to credentialed checks.

### Changed
- Improved VA scan ingestion by reading only required and scanner-specific optional columns for CSV and Excel inputs.
- Improved VA filtering performance by caching repeated regex masks during category resolution.
- Updated Rapid7 formatting to filter actionable findings by severity or CVSS score when available and sort by severity.
- Made VA reporting scanner-aware so shared summary and executive rollups work across Nessus and Rapid7.
- Fixed CLI VA scanner propagation so the selected scanner is passed into the analysis handler.
- Updated vulnerable dependency pins flagged by dependency audit:
  - `idna` from `3.11` to `3.15`.
  - `pyarrow` from `19.0.1` to `23.0.1`.
  - `urllib3` from `2.6.3` to `2.7.0`.

### Validation
- Verified module compilation with `python -m py_compile` across touched VA and handler modules.
- Verified Nessus and Rapid7 smoke paths, including credentialed and uncredentialed Nessus execution.
- Verified Rapid7 report writing with the bundled CSV sample.

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
