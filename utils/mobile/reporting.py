from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Iterable

from .models import Finding
from utils.shared.text_formatting import section_header, wrap_text_block


class MobileReportingMixin:
    """Report writing and summary presentation helpers."""

    REPORT_WRAP_WIDTH = 108
    BASE64_WRAP_WIDTH = 84

    @classmethod
    def _header(cls, title: str) -> str:
        return section_header(title, width=cls.REPORT_WRAP_WIDTH, fill="=")

    @classmethod
    def _write_field(
        cls,
        fh,
        label: str,
        value: object,
        *,
        wrap_width: int | None = None,
        indent: str = "  ",
        subsequent_indent: str = "      ",
    ) -> None:
        field_value = "" if value is None else str(value)
        width = wrap_width or cls.REPORT_WRAP_WIDTH - len(subsequent_indent)
        wrapped = wrap_text_block(
            field_value,
            width=width,
            initial_indent=indent,
            subsequent_indent=subsequent_indent,
        )
        fh.write(f"{label}:\n")
        if wrapped.strip():
            fh.write(f"{wrapped}\n")
        else:
            fh.write(f"{indent}<empty>\n")

    @classmethod
    def _format_quoted_base64(cls, encoded_text: str, indent: str = "  ") -> str:
        normalized = re.sub(r"\s+", "", str(encoded_text))
        chunks = [
            normalized[idx: idx + cls.BASE64_WRAP_WIDTH]
            for idx in range(0, len(normalized), cls.BASE64_WRAP_WIDTH)
        ] or [""]
        if len(chunks) == 1:
            return f'{indent}"{chunks[0]}"'

        lines = [f'{indent}"{chunks[0]}']
        for chunk in chunks[1:-1]:
            lines.append(f"{indent} {chunk}")
        lines.append(f'{indent} {chunks[-1]}"')
        return "\n".join(lines)

    @staticmethod
    def _format_kv_block(heading: str, fields: list[tuple[str, object]]) -> str:
        """Render a heading with indented key/value lines for console output."""
        lines = [f"{heading}:"]
        for key, value in fields:
            wrapped = wrap_text_block(
                f"{key}={value}",
                width=96,
                initial_indent="        ",
                subsequent_indent="          ",
            )
            lines.extend(wrapped.splitlines())
        return "\n".join(lines)

    @staticmethod
    def _taxonomy_tags_for_finding(
        finding: Finding,
        taxonomy_profile: str = "balanced",
    ) -> tuple[list[str], list[str], str, list[str]]:
        profile = str(taxonomy_profile or "balanced").strip().lower()
        if profile not in {"strict", "balanced", "aggressive"}:
            profile = "balanced"

        category = str(finding.category).lower()
        title = str(finding.title).lower()
        evidence = str(finding.evidence).lower()
        text = f"{title} {evidence}"

        masvs: set[str] = set()
        mastg: set[str] = set()
        matched_signals: list[str] = []
        score = 0

        category_rules = {
            "network_security": ("MASVS-NETWORK", "MASTG-NETWORK"),
            "tls": ("MASVS-NETWORK", "MASTG-NETWORK"),
            "pinning": ("MASVS-NETWORK", "MASTG-NETWORK"),
            "webview": ("MASVS-NETWORK", "MASTG-NETWORK"),
            "deeplink": ("MASVS-NETWORK", "MASTG-NETWORK"),
            "crypto": ("MASVS-CRYPTO", "MASTG-CRYPTO"),
            "hardcoded_secret": ("MASVS-STORAGE", "MASTG-STORAGE"),
            "secure_storage": ("MASVS-STORAGE", "MASTG-STORAGE"),
            "backup": ("MASVS-STORAGE", "MASTG-STORAGE"),
            "data_access": ("MASVS-STORAGE", "MASTG-STORAGE"),
            "component_exposure": ("MASVS-PLATFORM", "MASTG-PLATFORM"),
            "intent_security": ("MASVS-PLATFORM", "MASTG-PLATFORM"),
            "anti_debug": ("MASVS-PLATFORM", "MASTG-PLATFORM"),
            "anti_root": ("MASVS-RESILIENCE", "MASTG-RESILIENCE"),
            "anti_tamper": ("MASVS-RESILIENCE", "MASTG-RESILIENCE"),
            "integrity": ("MASVS-RESILIENCE", "MASTG-RESILIENCE"),
            "api_key_exposure": ("MASVS-AUTH", "MASTG-AUTH"),
            "logging": ("MASVS-PRIVACY", "MASTG-PRIVACY"),
        }

        if category in category_rules:
            masvs_tag, mastg_tag = category_rules[category]
            masvs.add(masvs_tag)
            mastg.add(mastg_tag)
            matched_signals.append(f"category:{category}")
            score += 2

        if category in {"hardcoded_secret"}:
            masvs.add("MASVS-AUTH")
            mastg.add("MASTG-AUTH")
            matched_signals.append("category:hardcoded_secret_auth_overlap")
            score += 1

        if profile in {"balanced", "aggressive"}:
            keyword_rules: tuple[tuple[tuple[str, ...], tuple[str, str]], ...] = (
                (("biometric", "face id", "touch id", "fingerprint"), ("MASVS-AUTH", "MASTG-AUTH")),
                (("taskjacking", "task affinity", "exported", "intent"), ("MASVS-PLATFORM", "MASTG-PLATFORM")),
                (("cleartext", "ssl", "tls", "pinning", "ats"), ("MASVS-NETWORK", "MASTG-NETWORK")),
                (("token", "api key", "secret", "credential"), ("MASVS-AUTH", "MASTG-AUTH")),
                (("keychain", "keystore", "sharedpreferences", "backup"), ("MASVS-STORAGE", "MASTG-STORAGE")),
                (("jailbreak", "root", "anti-debug", "tamper"), ("MASVS-RESILIENCE", "MASTG-RESILIENCE")),
                (("privacy", "clipboard", "pasteboard", "log"), ("MASVS-PRIVACY", "MASTG-PRIVACY")),
            )
            for needles, tags in keyword_rules:
                if any(needle in text for needle in needles):
                    masvs.add(tags[0])
                    mastg.add(tags[1])
                    matched_signals.append(f"keyword:{needles[0]}")
                    score += 1

        if profile == "aggressive":
            if "critical" in str(finding.severity).lower() or "high" in str(finding.severity).lower():
                if not any(tag.startswith("MASVS-") for tag in masvs):
                    masvs.add("MASVS-PLATFORM")
                    mastg.add("MASTG-PLATFORM")
                    matched_signals.append("aggressive:severity_fallback")
                    score += 1
            if "http://" in evidence and "MASVS-NETWORK" not in masvs:
                masvs.add("MASVS-NETWORK")
                mastg.add("MASTG-NETWORK")
                matched_signals.append("aggressive:http_signal")
                score += 1

        if profile == "strict":
            matched_signals = [signal for signal in matched_signals if signal.startswith("category:")]
            if not matched_signals:
                return [], [], "none", []
            confidence = "high"
        else:
            if score >= 4:
                confidence = "high"
            elif score >= 2:
                confidence = "medium"
            else:
                confidence = "low"

        return sorted(masvs), sorted(mastg), confidence, matched_signals

    @staticmethod
    def _poc_needle_for_finding(finding: Finding) -> str:
        title = str(finding.title).lower()
        title_needles = {
            "manifest debuggable enabled": 'android:debuggable="true"',
            "manifest backup enabled": 'android:allowBackup="true"',
            "manifest cleartext traffic enabled": 'android:usesCleartextTraffic="true"',
            "network security config allows cleartext traffic": "cleartextTrafficPermitted=\"true\"",
            "ats arbitrary loads enabled": "NSAllowsArbitraryLoads",
            "ats arbitrary loads detected": "NSAllowsArbitraryLoads",
            "debug entitlement enabled": "get-task-allow",
            "ios file sharing enabled": "UIFileSharingEnabled",
            "legacy external storage access requested": "requestLegacyExternalStorage",
            "app links missing autoverify": "android:autoVerify",
            "exported component without permission": "android:exported=\"true\"",
            "weak hash algorithm usage": "MessageDigest.getInstance(\"MD5\")",
            "weak cipher mode (ecb) usage": "Cipher.getInstance(\"ECB\")",
            "embedded private key material": "BEGIN PRIVATE KEY",
        }
        if title in title_needles:
            return title_needles[title]

        evidence = " ".join(str(finding.evidence).split())
        if evidence:
            token_match = re.search(r"[A-Za-z_][A-Za-z0-9_\-:.\"/=]{7,}", evidence)
            if token_match:
                return token_match.group(0)
            return evidence[:120]
        return finding.title

    def _taxonomy_poc_command(self, extraction_root: Path, finding: Finding) -> str:
        needle = self._poc_needle_for_finding(finding)
        root = Path(extraction_root)
        if finding.file and finding.file != "global":
            target = root / finding.file
        else:
            target = root
        return (
            "rg -n --no-heading -i --fixed-strings "
            f"{shlex.quote(needle)} {shlex.quote(str(target))}"
        )

    def _build_masvs_mastg_report(
        self,
        findings: list[Finding],
        platform: str,
        extraction_root: Path,
        taxonomy_mode: str,
        taxonomy_profile: str,
        application: str,
    ) -> dict:
        mode = str(taxonomy_mode or "both").strip().lower()
        if mode not in {"none", "masvs", "mastg", "both"}:
            mode = "both"
        if mode == "none":
            return {}
        profile = str(taxonomy_profile or "balanced").strip().lower()
        if profile not in {"strict", "balanced", "aggressive"}:
            profile = "balanced"

        entries = []
        masvs_counter: dict[str, int] = {}
        mastg_counter: dict[str, int] = {}
        confidence_counter: dict[str, int] = {}

        for index, finding in enumerate(findings, 1):
            masvs_tags, mastg_tags, confidence, matched_signals = self._taxonomy_tags_for_finding(
                finding,
                taxonomy_profile=profile,
            )
            if mode == "masvs":
                mastg_tags = []
            elif mode == "mastg":
                masvs_tags = []

            if not masvs_tags and not mastg_tags:
                continue

            confidence_counter[confidence] = confidence_counter.get(confidence, 0) + 1
            for tag in masvs_tags:
                masvs_counter[tag] = masvs_counter.get(tag, 0) + 1
            for tag in mastg_tags:
                mastg_counter[tag] = mastg_counter.get(tag, 0) + 1

            entries.append(
                {
                    "id": index,
                    "severity": finding.severity,
                    "category": finding.category,
                    "title": finding.title,
                    "file": finding.file,
                    "evidence": finding.evidence,
                    "masvs": masvs_tags,
                    "mastg": mastg_tags,
                    "mapping_confidence": confidence,
                    "mapping_signals": matched_signals,
                    "poc_command": self._taxonomy_poc_command(extraction_root, finding),
                }
            )

        if not entries:
            return {}

        return {
            "application": application,
            "platform": platform,
            "taxonomy_mode": mode,
            "taxonomy_profile": profile,
            "summary": {
                "tagged_findings": len(entries),
                "masvs_tag_counts": dict(sorted(masvs_counter.items())),
                "mastg_tag_counts": dict(sorted(mastg_counter.items())),
                "mapping_confidence_counts": dict(sorted(confidence_counter.items())),
            },
            "entries": entries,
        }

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
        seen_values = set()
        deduped_findings: list[Finding] = []
        for finding in findings:
            value_key = (finding.category.lower(), finding.title.lower(), finding.evidence.strip().lower())
            if value_key in seen_values:
                continue
            seen_values.add(value_key)
            deduped_findings.append(finding)

        if not deduped_findings:
            return 0

        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"{self._header('Findings Report')}\n")
            for index, finding in enumerate(deduped_findings, 1):
                fh.write(f"\n{self._header(f'Finding {index}')}\n")
                self._write_field(fh, "SEVERITY", finding.severity)
                self._write_field(fh, "CATEGORY", finding.category)
                self._write_field(fh, "TITLE", finding.title)
                self._write_field(fh, "FILE", finding.file)
                self._write_field(
                    fh,
                    "EVIDENCE",
                    finding.evidence,
                    wrap_width=self.REPORT_WRAP_WIDTH - 8,
                    indent="    ",
                    subsequent_indent="    ",
                )
        return len(deduped_findings)

    @staticmethod
    def _write_api_check_report(path: Path, lines: Iterable[str]) -> int:
        blocks = [str(line).strip("\n") for line in lines if str(line).strip()]
        if not blocks:
            return 0

        unique_blocks = list(dict.fromkeys(blocks))

        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"{MobileReportingMixin._header('API Key Checklist')}\n")
            for index, block in enumerate(unique_blocks, 1):
                fh.write(f"\n{MobileReportingMixin._header(f'API Check {index}')}\n")
                wrapped = wrap_text_block(
                    block,
                    width=100,
                    initial_indent="  ",
                    subsequent_indent="    ",
                )
                fh.write(f"{wrapped}\n")
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
            fh.write(f"{MobileReportingMixin._header('Base64 Findings')}\n")
            for index, (encoded_decoded, files) in enumerate(sorted_entries, 1):
                encoded_text, decoded_text, decoded_format = encoded_decoded
                ordered_files = sorted(files)
                fh.write(f"\n===== BASE64 FINDING {index} START =====\n")
                fh.write(f"\n{MobileReportingMixin._header(f'Base64 Finding {index}')}\n")
                MobileReportingMixin._write_field(
                    fh,
                    "FILES",
                    "\n".join(f"- {name}" for name in ordered_files),
                    indent="    ",
                    subsequent_indent="    ",
                )
                MobileReportingMixin._write_field(
                    fh, "FILE COUNT", len(ordered_files), indent="    ", subsequent_indent="    "
                )
                MobileReportingMixin._write_field(
                    fh, "FORMAT", decoded_format, indent="    ", subsequent_indent="    "
                )

                fh.write("ENCODED:\n")
                fh.write(f"{MobileReportingMixin._format_quoted_base64(encoded_text, indent='    ')}\n")
                MobileReportingMixin._write_field(
                    fh,
                    "DECODED",
                    decoded_text,
                    wrap_width=100,
                    indent="    ",
                    subsequent_indent="      ",
                )
                fh.write(f"===== BASE64 FINDING {index} END =====\n")
        return len(sorted_entries)

    @staticmethod
    def _write_obfuscated_string_map(
        path: Path,
        resource_map: dict[int, dict],
        references: Iterable[dict],
    ) -> int:
        if not resource_map:
            return 0

        usage: dict[int, dict[str, set[str]]] = {}
        for ref in references:
            if not isinstance(ref, dict):
                continue
            try:
                resource_id = int(ref.get("id"))
            except (TypeError, ValueError):
                continue
            if resource_id not in resource_map:
                continue
            usage.setdefault(resource_id, {"files": set(), "tokens": set()})
            source_file = str(ref.get("file", "")).strip()
            token = str(ref.get("token", "")).strip()
            if source_file:
                usage[resource_id]["files"].add(source_file)
            if token:
                usage[resource_id]["tokens"].add(token)

        if not usage:
            return 0

        written = 0
        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"{MobileReportingMixin._header('Obfuscated String References')}\n")
            for resource_id in sorted(usage):
                meta = resource_map.get(resource_id, {})
                value = str(meta.get("value", "")).replace("\r", "").replace("\n", "\\n").strip()
                if not value:
                    continue
                resource_name = str(meta.get("name", "")).strip() or "<unknown>"
                hex_value = str(meta.get("hex", f"0x{resource_id:08x}")).strip()
                source = str(meta.get("source", "")).strip()
                files = sorted(usage[resource_id]["files"])
                tokens = sorted(usage[resource_id]["tokens"])

                fh.write(f"\n{MobileReportingMixin._header(f'Resource {resource_id}')}\n")
                MobileReportingMixin._write_field(
                    fh,
                    "RESOURCE",
                    f"id={resource_id} hex={hex_value} name={resource_name}",
                    indent="    ",
                    subsequent_indent="      ",
                )
                if source:
                    MobileReportingMixin._write_field(
                        fh, "SOURCE", source, indent="    ", subsequent_indent="      "
                    )
                MobileReportingMixin._write_field(
                    fh, "VALUE", value, indent="    ", subsequent_indent="      "
                )
                MobileReportingMixin._write_field(
                    fh, "REFERENCE COUNT", len(files), indent="    ", subsequent_indent="      "
                )
                if files:
                    display_files = "\n".join(f"- {name}" for name in files[:8])
                    if len(files) > 8:
                        display_files = f"{display_files}\n- ... ({len(files) - 8} more)"
                    MobileReportingMixin._write_field(
                        fh, "FILES", display_files, indent="    ", subsequent_indent="      "
                    )
                if tokens:
                    display_tokens = "\n".join(f"- {token}" for token in tokens[:8])
                    if len(tokens) > 8:
                        display_tokens = f"{display_tokens}\n- ... ({len(tokens) - 8} more)"
                    MobileReportingMixin._write_field(
                        fh, "TOKENS", display_tokens, indent="    ", subsequent_indent="      "
                    )
                written += 1

        return written

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
        summary_message = self._format_kv_block(
            "Mobile static analysis summary",
            [
                ("files", summary["files_scanned"]),
                ("skipped", summary["files_skipped"]),
                ("urls", summary["url_count"]),
                ("ips", summary["ip_count"]),
                ("hardcoded", summary["hardcoded_count"]),
                ("api_key_checks", summary.get("api_key_assessment_count", 0)),
                ("api_key_issues", summary.get("api_key_issue_count", 0)),
                ("base64", summary["base64_count"]),
                ("obfuscated_string_refs", summary.get("obfuscated_string_refs_count", 0)),
                ("risk_findings", summary["risk_count"]),
                ("integrity_controls", summary["control_count"]),
                ("taxonomy_tagged", summary.get("taxonomy_tagged_count", 0)),
            ],
        )
        self.print_success_message(
            summary_message
        )
        if scoring:
            risk_message = self._format_kv_block(
                "Risk scoring",
                [
                    ("risk_score", scoring.get("risk_score")),
                    ("security_posture_score", scoring.get("security_posture_score")),
                    ("band", scoring.get("risk_band")),
                ],
            )
            self.print_info_message(
                risk_message
            )
        if summary.get("taxonomy_mode") and summary.get("taxonomy_mode") != "none":
            taxonomy_message = self._format_kv_block(
                "Taxonomy mapping",
                [
                    ("mode", summary.get("taxonomy_mode")),
                    ("profile", summary.get("taxonomy_profile", "balanced")),
                    ("tagged_findings", summary.get("taxonomy_tagged_count", 0)),
                ],
            )
            self.print_info_message(
                taxonomy_message
            )

        if summary["top_risks"]:
            self.print_info_message("Top risk findings:")
            for row in summary["top_risks"]:
                print(f"  - {row}")

        if summary["top_controls"]:
            self.print_info_message("Detected integrity/security controls:")
            for row in summary["top_controls"]:
                print(f"  - {row}")
