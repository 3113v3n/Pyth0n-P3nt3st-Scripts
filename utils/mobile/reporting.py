from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .models import Finding


class MobileReportingMixin:
    """Report writing and summary presentation helpers."""

    @staticmethod
    def _write_lines(path: Path, lines: Iterable[str]) -> int:
        filtered_lines = [str(line).rstrip("\n") for line in lines if str(line).strip()]
        if not filtered_lines:
            return 0

        unique_lines = list(dict.fromkeys(filtered_lines))

        count = 0
        with path.open("w", encoding="utf-8") as fh:
            for line in unique_lines:
                fh.write(f"{line}\n")
                count += 1
        return count

    def _write_findings_report(self, path: Path, findings: list[Finding]) -> int:
        rows = []
        seen_values = set()
        for finding in findings:
            value_key = (finding.category.lower(), finding.title.lower(), finding.evidence.strip().lower())
            if value_key in seen_values:
                continue
            seen_values.add(value_key)
            rows.append(
                f"[{finding.severity.upper()}] {finding.category} | {finding.title} | {finding.file} | {finding.evidence}"
            )
        return self._write_lines(path, rows)

    @staticmethod
    def _write_api_check_report(path: Path, lines: Iterable[str]) -> int:
        blocks = [str(line).strip("\n") for line in lines if str(line).strip()]
        if not blocks:
            return 0

        unique_blocks = list(dict.fromkeys(blocks))

        with path.open("w", encoding="utf-8") as fh:
            for index, block in enumerate(unique_blocks, 1):
                fh.write(f"{block}\n")
                if index < len(unique_blocks):
                    fh.write("\n")
        return len(unique_blocks)

    @staticmethod
    def _write_base64_report(path: Path, entries: Iterable[dict]) -> int:
        grouped: dict[tuple[str, str, str], set[str]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            encoded_text = str(entry.get("encoded", "")).strip()
            decoded_text = str(entry.get("decoded", "")).strip("\n")
            decoded_format = str(entry.get("format", "text") or "text").strip()
            source_file = str(entry.get("file", "")).strip()
            if not encoded_text or not decoded_text or not source_file:
                continue
            key = (encoded_text, decoded_text, decoded_format)
            grouped.setdefault(key, set()).add(source_file)

        if not grouped:
            return 0

        sorted_entries = sorted(
            grouped.items(),
            key=lambda item: (
                min(item[1]) if item[1] else "",
                item[0][2],
                item[0][0][:40],
            ),
        )

        with path.open("w", encoding="utf-8") as fh:
            for encoded_decoded, files in sorted_entries:
                encoded_text, decoded_text, decoded_format = encoded_decoded
                ordered_files = sorted(files)

                fh.write("===== BASE64 FINDING START =====\n\n")
                fh.write("FILE:\n")
                for file_name in ordered_files:
                    fh.write(f"  - {file_name}\n")
                fh.write(f"FILE COUNT: {len(ordered_files)}\n")
                fh.write(f"FORMAT: {decoded_format}\n")
                fh.write("ENCODED:\n")
                fh.write(f"  {encoded_text}\n")
                fh.write("DECODED:\n")
                decoded_lines = decoded_text.splitlines() or [decoded_text]
                for line in decoded_lines:
                    fh.write(f"  {line}\n")
                fh.write("\n")
                fh.write("===== BASE64 FINDING END =====\n\n")
        return len(sorted_entries)

    @staticmethod
    def _cleanup_previous_reports(output_dir: str, app_name: str, platform: str) -> None:
        base = Path(output_dir)
        patterns = [
            f"{app_name}_{platform}_*.txt",
            f"{app_name}_{platform}_*.json",
        ]
        for pattern in patterns:
            for path in base.glob(pattern):
                try:
                    path.unlink()
                except OSError:
                    continue

    def _console_summary(self, summary: dict) -> None:
        scoring = summary.get("scoring", {})
        self.print_success_message(
            (
                "Mobile static analysis summary: "
                f"files={summary['files_scanned']} skipped={summary['files_skipped']} "
                f"urls={summary['url_count']} ips={summary['ip_count']} "
                f"hardcoded={summary['hardcoded_count']} "
                f"api_key_checks={summary.get('api_key_assessment_count', 0)} "
                f"api_key_issues={summary.get('api_key_issue_count', 0)} "
                f"base64={summary['base64_count']} "
                f"risk_findings={summary['risk_count']} integrity_controls={summary['control_count']}"
            )
        )
        if scoring:
            self.print_info_message(
                "Risk scoring: "
                f"risk_score={scoring.get('risk_score')} "
                f"security_posture_score={scoring.get('security_posture_score')} "
                f"band={scoring.get('risk_band')}"
            )

        if summary["top_risks"]:
            self.print_info_message("Top risk findings:")
            for row in summary["top_risks"]:
                print(f"  - {row}")

        if summary["top_controls"]:
            self.print_info_message("Detected integrity/security controls:")
            for row in summary["top_controls"]:
                print(f"  - {row}")
