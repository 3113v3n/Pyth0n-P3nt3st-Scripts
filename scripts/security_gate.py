#!/usr/bin/env python3
"""Lightweight security gate for code diffs, commit metadata, and PR metadata."""

from __future__ import annotations

import argparse
import py_compile
import re
import subprocess
from pathlib import Path


ALLOW_MARKERS = {
    "shell_true": "security-gate: allow-shell-true",
    "dynamic_exec": "security-gate: allow-dynamic-exec",
}

COMMIT_REQUIRED_TRAILERS: tuple[str, ...] = (
    "Security-Checklist",
    "Security-Impact",
    "Security-Tests",
)

PR_CHECKLIST_ITEMS: tuple[str, ...] = (
    "Threat-model input paths and trust boundaries",
    "Validate/sanitize all external or user-controlled inputs",
    "Avoid shell=True and unsafe subprocess patterns (security-gate: allow-shell-true)",
    "Use least-privilege file handling and safe path resolution",
    "Prevent traversal and symlink clobbering on file writes",
    "Avoid leaking secrets in logs/output/errors",
    "Keep dependency and cryptographic usage safe and modern",
    "Add guardrails for failure modes",
    "Run targeted checks/tests and capture security-impact notes",
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private Key Header", re.compile(r"-----BEGIN(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----")),
)

RISK_PATTERNS: tuple[tuple[str, re.Pattern[str], str | None], ...] = (
    ("shell=True in subprocess (security-gate: allow-shell-true)", re.compile(r"\bshell\s*=\s*True\b"), ALLOW_MARKERS["shell_true"]),
    ("os.system usage", re.compile(r"\bos\.system\s*\("), None),
    ("eval usage", re.compile(r"\beval\s*\("), ALLOW_MARKERS["dynamic_exec"]),
    ("exec usage", re.compile(r"\bexec\s*\("), ALLOW_MARKERS["dynamic_exec"]),
    ("pickle.loads usage", re.compile(r"\bpickle\.loads\s*\("), None),
    ("yaml.load usage", re.compile(r"\byaml\.load\s*\("), None),
)


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _changed_files(staged: bool, diff_base: str | None) -> list[Path]:
    if staged:
        output = _run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    elif diff_base:
        output = _run_git(["diff", "--name-only", "--diff-filter=ACMR", f"{diff_base}...HEAD"])
    else:
        output = _run_git(["diff", "--name-only", "--diff-filter=ACMR"])
    return [Path(line.strip()) for line in output.splitlines() if line.strip()]


def _added_lines(staged: bool, diff_base: str | None) -> list[tuple[str, int, str]]:
    if staged:
        args = ["diff", "--cached", "-U0", "--no-color"]
    elif diff_base:
        args = ["diff", "-U0", "--no-color", f"{diff_base}...HEAD"]
    else:
        args = ["diff", "-U0", "--no-color"]
    patch = _run_git(args)

    findings: list[tuple[str, int, str]] = []
    current_file = ""
    new_line_no = 0

    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    for raw in patch.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw[6:].strip()
            continue
        if raw.startswith("@@"):
            match = hunk_re.match(raw)
            if match:
                new_line_no = int(match.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            findings.append((current_file, new_line_no, raw[1:]))
            new_line_no += 1
        elif raw.startswith(" ") or raw.startswith("-"):
            if raw.startswith(" "):
                new_line_no += 1
    return findings


def _check_py_compile(files: list[Path]) -> list[str]:
    errors: list[str] = []
    for file in files:
        if file.suffix != ".py" or not file.exists():
            continue
        try:
            py_compile.compile(str(file), doraise=True)
        except py_compile.PyCompileError as error:
            errors.append(f"[py_compile] {file}: {error.msg}")
    return errors


def _line_has_allow_marker(line: str, marker: str | None) -> bool:
    if not marker:
        return False
    return marker in line


def _scan_added_lines(added_lines: list[tuple[str, int, str]]) -> list[str]:
    issues: list[str] = []
    for file_path, line_no, line in added_lines:
        stripped = line.strip()
        if not stripped:
            continue

        for risk_name, pattern, allow_marker in RISK_PATTERNS:
            if not pattern.search(line):
                continue
            if _line_has_allow_marker(line, allow_marker):
                continue
            if risk_name == "yaml.load usage" and "SafeLoader" in line:
                continue
            issues.append(f"[{risk_name}] {file_path}:{line_no}: {stripped}")

        for secret_name, secret_re in SECRET_PATTERNS:
            if secret_re.search(line):
                issues.append(f"[hardcoded secret: {secret_name}] {file_path}:{line_no}: {stripped}")
    return issues


def _normalize_commit_message(text: str) -> str:
    # Ignore commit template comments.
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines).strip()


def _extract_trailer_value(text: str, key: str) -> str | None:
    pattern = re.compile(rf"(?im)^{re.escape(key)}\s*:\s*(.+)$")
    matches = pattern.findall(text)
    if not matches:
        return None
    value = matches[-1].strip()
    return value or None


def _check_commit_message_text(text: str, source_name: str) -> list[str]:
    issues: list[str] = []
    normalized = _normalize_commit_message(text)
    if not normalized:
        return [f"[commit metadata] {source_name}: commit message is empty."]

    checklist_value = _extract_trailer_value(normalized, "Security-Checklist")
    if checklist_value is None:
        issues.append(
            f"[commit metadata] {source_name}: missing trailer 'Security-Checklist: done'."
        )
    else:
        lowered = checklist_value.lower()
        if not any(token in lowered for token in ("done", "yes", "ack", "complete", "true")):
            issues.append(
                f"[commit metadata] {source_name}: Security-Checklist must acknowledge completion (for example: 'done')."
            )

    for key in COMMIT_REQUIRED_TRAILERS:
        if key == "Security-Checklist":
            continue
        value = _extract_trailer_value(normalized, key)
        if value is None:
            issues.append(f"[commit metadata] {source_name}: missing trailer '{key}: <value>'.")
            continue
        if value in {"<summary>", "<commands/results>", "<value>"}:
            issues.append(
                f"[commit metadata] {source_name}: trailer '{key}' must be replaced with concrete details."
            )

    return issues


def _check_commit_message_file(path: Path) -> list[str]:
    if not path.exists():
        return [f"[commit metadata] {path}: file not found."]
    return _check_commit_message_text(_read_text_file(path), str(path))


def _commit_shas_in_range(base: str) -> list[str]:
    output = _run_git(["rev-list", "--reverse", f"{base}..HEAD"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _check_commit_range(base: str) -> list[str]:
    issues: list[str] = []
    for sha in _commit_shas_in_range(base):
        message = _run_git(["show", "-s", "--format=%B", sha])
        source = f"commit {sha[:12]}"
        issues.extend(_check_commit_message_text(message, source))
    return issues


def _extract_single_line_field(text: str, field_name: str) -> str | None:
    match = re.search(rf"(?im)^{re.escape(field_name)}\s*:\s*(.+)$", text)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _check_pr_body_text(text: str, source_name: str) -> list[str]:
    issues: list[str] = []
    if not text.strip():
        return [f"[pr metadata] {source_name}: PR body is empty."]

    for item in PR_CHECKLIST_ITEMS:
        checked_pattern = re.compile(
            rf"(?im)^-\s*\[[xX]\]\s+.*{re.escape(item)}"
        )
        if not checked_pattern.search(text):
            issues.append(f"[pr metadata] {source_name}: unchecked or missing checklist item: '{item}'.")

    security_impact = _extract_single_line_field(text, "Security impact")
    if security_impact is None:
        issues.append("[pr metadata] PR body is missing 'Security impact: <summary>'.")
    elif security_impact in {"<summary>", "<none|low|medium|high>", "tbd", "todo"}:
        issues.append("[pr metadata] 'Security impact' must include concrete details.")

    security_tests = _extract_single_line_field(text, "Security tests")
    if security_tests is None:
        issues.append("[pr metadata] PR body is missing 'Security tests: <commands/results>'.")
    elif security_tests in {"<commands/results>", "tbd", "todo"}:
        issues.append("[pr metadata] 'Security tests' must include concrete details.")

    return issues


def _check_pr_body_file(path: Path) -> list[str]:
    if not path.exists():
        return [f"[pr metadata] {path}: file not found."]
    return _check_pr_body_text(_read_text_file(path), str(path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security gate for changed code, commit metadata, and PR metadata."
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Check staged changes only.",
    )
    parser.add_argument(
        "--diff-base",
        type=str,
        default="",
        help="Check code diff from <base>...HEAD (for CI/PR use).",
    )
    parser.add_argument(
        "--check-commit-msg-file",
        type=Path,
        default=None,
        help="Validate mandatory security trailers in a commit message file.",
    )
    parser.add_argument(
        "--check-commit-range-base",
        type=str,
        default="",
        help="Validate mandatory security trailers for commits in <base>..HEAD.",
    )
    parser.add_argument(
        "--check-pr-body-file",
        type=Path,
        default=None,
        help="Validate mandatory security checklist content in a PR body file.",
    )
    args = parser.parse_args()

    issues: list[str] = []

    run_code_checks = bool(
        args.staged
        or args.diff_base
        or (
            args.check_commit_msg_file is None
            and not args.check_commit_range_base.strip()
            and args.check_pr_body_file is None
        )
    )

    if run_code_checks:
        staged = bool(args.staged or not args.diff_base)
        diff_base = args.diff_base.strip() or None
        files = _changed_files(staged=staged, diff_base=diff_base)
        added_lines = _added_lines(staged=staged, diff_base=diff_base)
        issues.extend(_check_py_compile(files))
        issues.extend(_scan_added_lines(added_lines))

    if args.check_commit_msg_file is not None:
        issues.extend(_check_commit_message_file(args.check_commit_msg_file))

    commit_range_base = args.check_commit_range_base.strip()
    if commit_range_base:
        issues.extend(_check_commit_range(commit_range_base))

    if args.check_pr_body_file is not None:
        issues.extend(_check_pr_body_file(args.check_pr_body_file))

    if issues:
        print("[SECURITY GATE] BLOCKED")
        print(
            "Resolve the following issues or add an approved inline marker where explicitly allowed:"
        )
        for issue in issues:
            print(f" - {issue}")
        print("\nAllowed inline markers:")
        print(f" - {ALLOW_MARKERS['shell_true']}")
        print(f" - {ALLOW_MARKERS['dynamic_exec']}")
        return 1

    print("[SECURITY GATE] PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
