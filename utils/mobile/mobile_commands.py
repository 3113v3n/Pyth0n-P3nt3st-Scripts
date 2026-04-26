"""mobile_commands.py - Orchestration layer for mobile static analysis."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import hashlib
import json
import os

from handlers import FileHandler, ScreenHandler
from utils.shared import Commands, Config, CustomDecorators

from .api_key_checks import MobileApiKeyChecksMixin
from .extraction import MobileExtractionMixin
from .legacy_ops import MobileLegacyOpsMixin
from .models import Finding
from .nuclei import MobileNucleiMixin
from .reporting import MobileReportingMixin
from .static_scan import MobileStaticScanMixin


class MobileCommands(
    FileHandler,
    Config,
    Commands,
    ScreenHandler,
    CustomDecorators,
    MobileLegacyOpsMixin,
    MobileExtractionMixin,
    MobileStaticScanMixin,
    MobileApiKeyChecksMixin,
    MobileReportingMixin,
    MobileNucleiMixin,
):
    """Mobile static analysis commands for APK/IPA packages."""

    def __init__(self) -> None:
        super().__init__()
        self.mobile_output_dir = ""
        self.file_type = ""
        self.folder_name = ""
        self.file_name = ""
        self.file_count = 0
        self.templates_folder = ""
        self.debug = False
        self.grep_cmd = "grep"
        self.taxonomy_mode = "both"
        self.taxonomy_profile = "balanced"

        self._scan_stats: dict = {}
        self._nuclei_templates_synced = False

    @CustomDecorators.measure_execution_time
    def inspect_application_files(self, application: str, test_domain: str, operating_system: str):
        try:
            if operating_system == "darwin":
                self.update_grep_cmd()

            self.update_output_directory(test_domain)
            folder_name, extraction_method = self.decompile_application(application)

            self.create_subfolder()
            output_prefix = f"{self.mobile_output_dir}/{self.file_name}"

            self.rename_folders_with_spaces(folder_name)

            platform = "android" if self.file_type == "apk" else "ios"
            basename = f"{output_prefix}_{platform}"
            self._cleanup_previous_reports(self.mobile_output_dir, self.file_name, platform)

            root = Path(folder_name)
            workers = max(4, min(32, (os.cpu_count() or 4) * self.THREAD_FACTOR))

            urls: set[str] = set()
            ips: set[str] = set()
            hardcoded: list[Finding] = []
            base64_entries: list[dict] = []
            risk_findings: list[Finding] = []
            control_findings: list[Finding] = []

            bytes_scanned = 0
            files_skipped = 0
            self.file_count = 0

            with ThreadPoolExecutor(max_workers=workers) as executor:
                all_files = [path for path in root.rglob("*") if path.is_file()]
                self.file_count = len(all_files)
                futures = [executor.submit(self._scan_single_file, path, root) for path in all_files]
                for future in as_completed(futures):
                    scanned = future.result()
                    if scanned["skipped"]:
                        files_skipped += 1
                        continue

                    bytes_scanned += scanned["bytes_scanned"]
                    urls.update(scanned["urls"])
                    ips.update(scanned["ips"])
                    hardcoded.extend(scanned["hardcoded"])
                    base64_entries.extend(scanned["base64"])
                    risk_findings.extend(scanned["risk_findings"])
                    control_findings.extend(scanned["control_findings"])

            if platform == "android":
                m_risks, m_controls = self._scan_android_manifest(root)
            else:
                m_risks, m_controls = self._scan_ios_plist(root)
            risk_findings.extend(m_risks)
            control_findings.extend(m_controls)

            hardcoded = self._dedupe_findings(hardcoded)
            risk_findings = self._dedupe_findings(risk_findings)
            control_findings = self._dedupe_findings(control_findings)

            api_key_findings, api_key_report_lines = self._assess_discovered_api_keys(hardcoded)
            if api_key_findings:
                risk_findings.extend(api_key_findings)
                risk_findings = self._dedupe_findings(risk_findings)

            has_https_endpoint = any(url.lower().startswith("https://") for url in urls)
            has_pinning_signal = any(f.category == "pinning" for f in control_findings)
            if has_https_endpoint and not has_pinning_signal:
                risk_findings.append(
                    Finding(
                        category="pinning",
                        title="No Certificate Pinning Signal Detected (Heuristic)",
                        severity="low",
                        file="global",
                        evidence="HTTPS endpoints discovered, but no static pinning signal matched.",
                    )
                )
                risk_findings = self._dedupe_findings(risk_findings)

            combined_risk_findings = self._dedupe_findings(risk_findings + hardcoded)

            nuclei_meta = self.scan_with_nuclei(
                folder_name,
                self.mobile_output_dir,
                platform,
                use_cached_results=(extraction_method == "cached"),
            )

            urls_file = Path(f"{basename}_urls.txt")
            ips_file = Path(f"{basename}_ips.txt")
            hardcoded_file = Path(f"{basename}_hardcoded.txt")
            api_key_report_file = Path(f"{basename}_api_key_checklist.txt")
            base64_file = Path(f"{basename}_base64.txt")
            risk_file = Path(f"{basename}_integrity_findings.txt")
            control_file = Path(f"{basename}_integrity_controls.txt")
            summary_file = Path(f"{basename}_summary.json")
            taxonomy_file = Path(f"{basename}_masvs_mastg.json")

            sorted_urls = self._collapse_urls_to_common_bases(urls)
            sorted_ips = sorted(ips, key=lambda x: tuple(int(part) for part in x.split(".")))

            url_count = self._write_lines(urls_file, sorted_urls)
            ip_count = self._write_lines(ips_file, sorted_ips)
            hardcoded_count = self._write_findings_report(hardcoded_file, hardcoded)
            api_key_assessment_count = self._write_api_check_report(api_key_report_file, api_key_report_lines)
            base64_count = self._write_base64_report(base64_file, base64_entries)
            risk_count = self._write_findings_report(risk_file, risk_findings)
            control_count = self._write_findings_report(control_file, control_findings)
            taxonomy_report = self._build_masvs_mastg_report(
                findings=combined_risk_findings,
                platform=platform,
                extraction_root=root,
                taxonomy_mode=self.taxonomy_mode,
                taxonomy_profile=self.taxonomy_profile,
                application=os.path.basename(application),
            )
            taxonomy_tagged_count = 0
            if taxonomy_report.get("entries"):
                taxonomy_file.write_text(
                    json.dumps(taxonomy_report, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                taxonomy_tagged_count = len(taxonomy_report["entries"])
            reports = {}
            if url_count:
                reports["urls"] = str(urls_file)
            if ip_count:
                reports["ips"] = str(ips_file)
            if hardcoded_count:
                reports["hardcoded"] = str(hardcoded_file)
            if api_key_assessment_count:
                reports["api_key_checklist"] = str(api_key_report_file)
            if base64_count:
                reports["base64"] = str(base64_file)
            if risk_count:
                reports["integrity_findings"] = str(risk_file)
            if control_count:
                reports["integrity_controls"] = str(control_file)
            if taxonomy_tagged_count:
                reports["masvs_mastg"] = str(taxonomy_file)

            risk_counter = {}
            for finding in combined_risk_findings:
                key = f"{finding.title} ({finding.severity})"
                risk_counter[key] = risk_counter.get(key, 0) + 1

            control_counter = {}
            for finding in control_findings:
                key = f"{finding.title}"
                control_counter[key] = control_counter.get(key, 0) + 1

            top_risks = [f"{k}: {v}" for k, v in sorted(risk_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
            top_controls = [f"{k}: {v}" for k, v in sorted(control_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
            scoring = self._build_severity_score(combined_risk_findings)

            summary = {
                "application": os.path.basename(application),
                "application_sha256": hashlib.sha256(Path(application).read_bytes()).hexdigest(),
                "platform": platform,
                "extraction_method": extraction_method,
                "output_directory": self.mobile_output_dir,
                "files_scanned": self.file_count - files_skipped,
                "files_skipped": files_skipped,
                "bytes_scanned": bytes_scanned,
                "url_count": url_count,
                "ip_count": ip_count,
                "hardcoded_count": hardcoded_count,
                "api_key_assessment_count": api_key_assessment_count,
                "api_key_issue_count": len(api_key_findings),
                "base64_count": base64_count,
                "risk_count": risk_count,
                "control_count": control_count,
                "combined_risk_count": len(combined_risk_findings),
                "top_risks": top_risks,
                "top_controls": top_controls,
                "scoring": scoring,
                "nuclei": nuclei_meta,
                "taxonomy_mode": self.taxonomy_mode,
                "taxonomy_profile": self.taxonomy_profile,
                "taxonomy_tagged_count": taxonomy_tagged_count,
                "reports": reports,
            }

            summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            self._scan_stats = summary
            self._console_summary(summary)

            self.print_success_message(
                message="Application scanning complete, all files are located here:",
                mobile_success=self.mobile_output_dir,
            )

            self.flush_system()

        except Exception as error:
            self.print_error_message(message="Error during mobile assessment", exception_error=error)
        finally:
            self._cleanup_processes()

    def _cleanup_processes(self):
        try:
            self.flush_system("I/O")
        except Exception as error:
            self.print_error_message(message="Error during cleanup", exception_error=error)
