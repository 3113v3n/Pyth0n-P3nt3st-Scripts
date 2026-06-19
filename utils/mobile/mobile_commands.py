"""mobile_commands.py - Orchestration layer for mobile static analysis."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from handlers import FileHandler, ScreenHandler
from utils.shared import Commands, Config, CustomDecorators

from .api_key_checks import MobileApiKeyChecksMixin
from .extraction import MobileExtractionMixin
from .finding_pipeline_helpers import finalize_mobile_findings
from .legacy_ops import MobileLegacyOpsMixin
from .models import Finding
from .nuclei import MobileNucleiMixin
from .report_artifact_helpers import build_artifact_paths, write_taxonomy_report
from .reporting import MobileReportingMixin
from .scan_aggregation_helpers import aggregate_scan_results
from .static_scan import MobileStaticScanMixin
from .summary_helpers import build_reports_map, build_scan_summary, summarize_findings


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
        self._android_obfuscated_resource_map: dict[int, dict] = {}
        self._android_obfuscated_symbol_map: dict[str, set[int]] = {}

    @CustomDecorators.measure_execution_time
    def inspect_application_files(self, application: str, test_domain: str, operating_system: str):
        folder_name = ""
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
            if platform == "android":
                (
                    self._android_obfuscated_resource_map,
                    self._android_obfuscated_symbol_map,
                ) = self._build_android_obfuscated_maps(root)
            else:
                self._android_obfuscated_resource_map = {}
                self._android_obfuscated_symbol_map = {}

            urls: set[str] = set()
            ips: set[str] = set()
            hardcoded: list[Finding] = []
            obfuscated_refs: list[dict] = []
            base64_entries: list[dict] = []
            risk_findings: list[Finding] = []
            control_findings: list[Finding] = []

            self.file_count = 0

            with ThreadPoolExecutor(max_workers=workers) as executor:
                all_files = [path for path in root.rglob("*") if path.is_file()]
                self.file_count = len(all_files)
                futures = [executor.submit(self._scan_single_file, path, root) for path in all_files]
                scanned_results = [future.result() for future in as_completed(futures)]

            aggregated = aggregate_scan_results(scanned_results)
            urls = aggregated["urls"]
            ips = aggregated["ips"]
            hardcoded = aggregated["hardcoded"]
            obfuscated_refs = aggregated["obfuscated_refs"]
            base64_entries = aggregated["base64_entries"]
            risk_findings = aggregated["risk_findings"]
            control_findings = aggregated["control_findings"]
            bytes_scanned = aggregated["bytes_scanned"]
            files_skipped = aggregated["files_skipped"]

            if platform == "android":
                m_risks, m_controls = self._scan_android_manifest(root)
            else:
                m_risks, m_controls = self._scan_ios_plist(root)
            risk_findings.extend(m_risks)
            control_findings.extend(m_controls)

            finalized = finalize_mobile_findings(
                hardcoded=hardcoded,
                risk_findings=risk_findings,
                control_findings=control_findings,
                urls=urls,
                assess_discovered_api_keys=self._assess_discovered_api_keys,
                dedupe_findings=self._dedupe_findings,
            )
            hardcoded = finalized["hardcoded"]
            risk_findings = finalized["risk_findings"]
            control_findings = finalized["control_findings"]
            api_key_findings = finalized["api_key_findings"]
            api_key_report_lines = finalized["api_key_report_lines"]
            combined_risk_findings = finalized["combined_risk_findings"]

            nuclei_meta = self.scan_with_nuclei(
                folder_name,
                self.mobile_output_dir,
                platform,
                use_cached_results=(extraction_method == "cached"),
            )

            artifact_paths = build_artifact_paths(Path(basename))
            urls_file = artifact_paths["urls"]
            ips_file = artifact_paths["ips"]
            hardcoded_file = artifact_paths["hardcoded"]
            api_key_report_file = artifact_paths["api_key_checklist"]
            base64_file = artifact_paths["base64"]
            obfuscated_map_file = artifact_paths["obfuscated_string_map"]
            risk_file = artifact_paths["integrity_findings"]
            control_file = artifact_paths["integrity_controls"]
            summary_file = artifact_paths["summary"]
            taxonomy_file = artifact_paths["taxonomy"]

            sorted_urls = self._collapse_urls_to_common_bases(urls)
            sorted_ips = sorted(ips, key=lambda x: tuple(int(part) for part in x.split(".")))

            url_count = self._write_lines(urls_file, sorted_urls)
            ip_count = self._write_lines(ips_file, sorted_ips)
            hardcoded_count = self._write_findings_report(hardcoded_file, hardcoded)
            api_key_assessment_count = self._write_api_check_report(api_key_report_file, api_key_report_lines)
            base64_count = self._write_base64_report(base64_file, base64_entries)
            obfuscated_map_count = self._write_obfuscated_string_map(
                obfuscated_map_file,
                self._android_obfuscated_resource_map,
                obfuscated_refs,
            )
            risk_count = self._write_integrity_report(risk_file, risk_findings)
            control_count = self._write_integrity_report(control_file, control_findings)
            taxonomy_report = self._build_masvs_mastg_report(
                findings=combined_risk_findings,
                platform=platform,
                extraction_root=root,
                taxonomy_mode=self.taxonomy_mode,
                taxonomy_profile=self.taxonomy_profile,
                application=os.path.basename(application),
            )
            taxonomy_tagged_count = write_taxonomy_report(taxonomy_file, taxonomy_report)
            reports = build_reports_map(
                urls_file=urls_file,
                ips_file=ips_file,
                hardcoded_file=hardcoded_file,
                api_key_report_file=api_key_report_file,
                base64_file=base64_file,
                obfuscated_map_file=obfuscated_map_file,
                risk_file=risk_file,
                control_file=control_file,
                taxonomy_file=taxonomy_file,
                url_count=url_count,
                ip_count=ip_count,
                hardcoded_count=hardcoded_count,
                api_key_assessment_count=api_key_assessment_count,
                base64_count=base64_count,
                obfuscated_map_count=obfuscated_map_count,
                risk_count=risk_count,
                control_count=control_count,
                taxonomy_tagged_count=taxonomy_tagged_count,
            )

            top_risks, top_controls = summarize_findings(combined_risk_findings, control_findings)
            scoring = self._build_severity_score(combined_risk_findings)

            summary = build_scan_summary(
                application=Path(application),
                platform=platform,
                extraction_method=extraction_method,
                output_directory=self.mobile_output_dir,
                files_scanned=self.file_count - files_skipped,
                files_skipped=files_skipped,
                bytes_scanned=bytes_scanned,
                url_count=url_count,
                ip_count=ip_count,
                hardcoded_count=hardcoded_count,
                api_key_assessment_count=api_key_assessment_count,
                api_key_issue_count=len(api_key_findings),
                base64_count=base64_count,
                obfuscated_string_refs_count=obfuscated_map_count,
                risk_count=risk_count,
                control_count=control_count,
                combined_risk_count=len(combined_risk_findings),
                top_risks=top_risks,
                top_controls=top_controls,
                scoring=scoring,
                nuclei=nuclei_meta,
                taxonomy_mode=self.taxonomy_mode,
                taxonomy_profile=self.taxonomy_profile,
                taxonomy_tagged_count=taxonomy_tagged_count,
                reports=reports,
            )

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
            self.cleanup_runtime_artifacts(extracted_folder=folder_name, remove_templates=False)
            self._cleanup_processes()

    def _cleanup_processes(self):
        try:
            self.flush_system("I/O")
        except Exception as error:
            self.print_error_message(message="Error during cleanup", exception_error=error)

    def cleanup_runtime_artifacts(self, extracted_folder: str = "", remove_templates: bool = False) -> None:
        """Cleanup optional runtime artifacts while preserving decompiled app folders."""
        try:
            self.cleanup_extraction_folder(extracted_folder)
            if remove_templates:
                self.cleanup_nuclei_templates()
        except Exception as error:
            self.print_warning_message(
                "Runtime cleanup encountered an issue",
                file_path=str(error),
            )
