"""
reporting.py — Generate a consolidated markdown report from external phase
artifacts. The report is plain Markdown so it can be reviewed in a text editor
or rendered in any pull request / wiki tool.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .external_constants import (
    PHASE_PORTS,
    PHASE_PROBE,
    PHASE_RECON,
    PHASE_SCREENSHOTS,
    PHASE_TAKEOVER,
    PHASE_URLS,
    PHASE_VULNS,
)


# Phase metadata: title shown in the report and the result keys we summarise.
_PHASE_META = {
    PHASE_RECON: ("Subdomain Reconnaissance", ("subdomains_file", "resolved_file", "subdomain_count", "resolved_count")),
    PHASE_PROBE: ("HTTP Probing & Tech Detection", ("json_path", "txt_path", "count")),
    PHASE_PORTS: ("Port & Service Enumeration", ("normal", "grepable", "count")),
    PHASE_SCREENSHOTS: ("Web Screenshots", ("directory", "count")),
    PHASE_TAKEOVER: ("Subdomain Takeover Detection", ("output", "tool", "count")),
    PHASE_URLS: ("Historical URL Collection", ("urls", "sensitive", "url_count", "sensitive_count", "tool")),
    PHASE_VULNS: ("Vulnerability Scanning (nuclei)", ("output", "total", "severities")),
}


class ExternalReport:
    """Build a single markdown report summarising all phase artifacts."""

    def write(
        self,
        target_domain: str,
        run_dir: Path,
        phase_results: dict,
        ai_summary: str | None = None,
    ) -> Path:
        """Write the consolidated report to <run_dir>/external_report.md.

        Args:
            target_domain: Root domain that was assessed.
            run_dir:       Directory containing all phase artifacts.
            phase_results: Mapping of phase name → result dict.
            ai_summary:    Optional AI-generated narrative summary.

        Returns:
            Path to the generated report.
        """
        report_path = run_dir / "external_report.md"
        lines: list[str] = []
        lines.append(f"# External Assessment Report — {target_domain}")
        lines.append("")
        lines.append(f"_Generated: {datetime.now().isoformat(timespec='seconds')}_")
        lines.append("")
        lines.append(f"_Run directory: `{run_dir}`_")
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append(self._summary_table(phase_results))
        lines.append("")

        if ai_summary:
            lines.append("## AI-Assisted Summary")
            lines.append("")
            lines.append(ai_summary.strip())
            lines.append("")

        lines.append("## Phase Details")
        for phase, (title, _) in _PHASE_META.items():
            result = phase_results.get(phase)
            if not result:
                continue
            lines.append("")
            lines.append(f"### {title}")
            lines.append("")
            lines.extend(self._phase_section(phase, result))

        report_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return report_path

    def _summary_table(self, phase_results: dict) -> str:
        rows = ["| Phase | Status | Highlights |", "| --- | --- | --- |"]
        for phase, (title, _) in _PHASE_META.items():
            result = phase_results.get(phase)
            if not result:
                rows.append(f"| {title} | skipped | — |")
                continue
            if result.get("missing"):
                rows.append(f"| {title} | tool missing ({result['missing']}) | — |")
                continue
            rows.append(f"| {title} | completed | {self._highlight(phase, result)} |")
        return "\n".join(rows)

    @staticmethod
    def _highlight(phase: str, result: dict) -> str:
        if phase == PHASE_RECON:
            return f"{result.get('resolved_count', 0)} resolved / {result.get('subdomain_count', 0)} found"
        if phase == PHASE_PROBE:
            return f"{result.get('count', 0)} alive hosts"
        if phase == PHASE_PORTS:
            return f"{result.get('count', 0)} hosts scanned"
        if phase == PHASE_SCREENSHOTS:
            return f"{result.get('count', 0)} screenshots"
        if phase == PHASE_TAKEOVER:
            return f"{result.get('count', 0)} potential takeovers ({result.get('tool', 'n/a')})"
        if phase == PHASE_URLS:
            return f"{result.get('url_count', 0)} URLs / {result.get('sensitive_count', 0)} sensitive"
        if phase == PHASE_VULNS:
            severities = result.get("severities") or {}
            sev_str = ", ".join(f"{k}:{v}" for k, v in severities.items()) or "none"
            return f"{result.get('total', 0)} findings ({sev_str})"
        return "—"

    def _phase_section(self, phase: str, result: dict) -> list[str]:
        lines: list[str] = []
        if result.get("missing"):
            lines.append(f"_Skipped — required tool not installed: `{result['missing']}`._")
            return lines

        for key in _PHASE_META[phase][1]:
            value = result.get(key)
            if value in (None, 0, "", {}):
                continue
            if isinstance(value, dict):
                rendered = ", ".join(f"{k}={v}" for k, v in value.items())
                lines.append(f"- **{key}**: {rendered}")
                continue
            if isinstance(value, Path):
                lines.append(f"- **{key}**: `{value}`")
                continue
            lines.append(f"- **{key}**: {value}")
        if not lines:
            lines.append("_No artifacts produced._")
        return lines
