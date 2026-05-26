from __future__ import annotations

import json
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Finding


class MobileApiKeyChecksMixin:
    """Live and static API-key exposure assessment helpers."""

    @classmethod
    def _extract_unique_api_keys(cls, findings: list[Finding]) -> dict[str, dict[str, set[str]]]:
        discovered: dict[str, dict[str, set[str]]] = {}
        key_titles = {title for title, _ in cls.API_KEY_VALUE_PATTERNS}

        for finding in findings:
            if finding.title in key_titles or finding.title == "Hardcoded Credential Assignment":
                for key_title, pattern in cls.API_KEY_VALUE_PATTERNS:
                    if finding.title not in {key_title, "Hardcoded Credential Assignment"}:
                        continue
                    for token in pattern.findall(finding.evidence):
                        if not token:
                            continue
                        key_group = discovered.setdefault(key_title, {})
                        key_group.setdefault(token, set()).add(finding.file)

            if finding.title == "Hardcoded Credential Assignment":
                for token in cls.GENERIC_API_KEY_ASSIGNMENT_RE.findall(finding.evidence):
                    value = str(token).strip()
                    if not value or value.lower() in cls.NOISE_SECRET_VALUES:
                        continue
                    generic_group = discovered.setdefault("Generic API Key", {})
                    generic_group.setdefault(value, set()).add(finding.file)

        return discovered

    @classmethod
    def _api_key_check_meta(cls, check_id: str) -> dict[str, str]:
        for entry in cls.API_KEY_CHECKLIST:
            if entry.get("id") == check_id:
                return entry
        return {"id": check_id, "cwe": "N/A", "cve": "N/A", "cvss": "N/A"}

    @staticmethod
    def _http_json_request(
        url: str,
        timeout: int = 12,
        method: str = "GET",
        payload: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, str]:
        request_headers = {"User-Agent": "Mozilla/5.0"}
        if headers:
            request_headers.update(headers)
        data = None
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            headers=request_headers,
            data=data,
            method=method.upper(),
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(body) if body.strip() else {}
                return response.getcode(), parsed, ""
        except HTTPError as error:
            try:
                parsed = json.loads(error.read().decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, ValueError):
                parsed = {}
            return error.code, parsed, str(error)
        except (URLError, TimeoutError, OSError) as error:
            return 0, {}, str(error)

    @staticmethod
    def _init_api_report_record(key: str) -> dict:
        return {
            "key": key,
            "checklist": "hardcoded-key-exposure",
            "failed_checks": set(),
            "accessible_apis": set(),
            "tests": [],
            "poc_cmd": "",
            "poc_response": "",
        }

    @classmethod
    def _get_api_report_record(cls, records: dict[str, dict], key: str) -> dict:
        return records.setdefault(key, cls._init_api_report_record(key))

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        normalized = str(value).strip()
        if normalized and normalized not in items:
            items.append(normalized)

    @staticmethod
    def _json_preview(payload: dict, fallback: str = "no response body", max_len: int = 260) -> str:
        if isinstance(payload, dict) and payload:
            text = json.dumps(payload, ensure_ascii=True)
            return text if len(text) <= max_len else text[: max_len - 3] + "..."
        return fallback

    @classmethod
    def _render_api_key_report_blocks(cls, records: dict[str, dict]) -> list[str]:
        blocks: list[str] = []

        for key in sorted(records):
            record = records[key]
            tests = [test for test in record.get("tests", []) if str(test).strip()]
            if not tests:
                continue

            failed_checks = sorted(record.get("failed_checks", set()))
            accessible_apis = sorted(record.get("accessible_apis", set()))
            poc_cmd = record.get("poc_cmd") or "N/A"
            poc_response = record.get("poc_response") or "N/A"

            lines = [
                f"KEY: {record.get('key', key)}",
                "VULNERABLE_STATUS: Vulnerable",
                f"CHECKLIST: {record.get('checklist', 'hardcoded-key-exposure')}",
                "FAILED_CHECKS:",
            ]

            if failed_checks:
                for failed_check in failed_checks:
                    lines.append(f"        - {failed_check}")
            else:
                lines.append("        - none")

            lines.append("ACCESSIBLE_APIS:")
            if accessible_apis:
                for api in accessible_apis:
                    lines.append(f"        - {api}")
            else:
                lines.append("        - none")

            lines.append("TEST_CONDUCTED:")
            for test_name in tests:
                lines.append(f"        - {test_name}")

            lines.append(f"POC: {poc_cmd}")
            lines.append(f"     {poc_response}")
            blocks.append("\n".join(lines))

        return blocks

    def _assess_google_api_keys(
        self,
        google_keys: dict[str, set[str]],
        report_records: dict[str, dict],
    ) -> list[Finding]:
        if not google_keys:
            return []

        findings: list[Finding] = []
        restriction_meta = self._api_key_check_meta("restriction-controls")
        scope_meta = self._api_key_check_meta("least-privilege-api-scope")
        quota_meta = self._api_key_check_meta("quota-and-billing-abuse")

        for key in sorted(google_keys):
            masked_key = self.mask_secret(key)
            accessible_apis: list[str] = []
            restriction_detected = False
            invalid_key = False
            successful_tests: list[dict] = []
            test_cases = [
                {"name": name, "url": template.format(key=key), "method": "GET", "payload": None}
                for name, template in self.GOOGLE_API_TEST_ENDPOINTS
            ]
            test_cases.extend(
                [
                    {
                        "name": "firebase_identitytoolkit_lookup",
                        "url": f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={key}",
                        "method": "POST",
                        "payload": {"idToken": "invalid"},
                    },
                    {
                        "name": "cloud_translate_languages",
                        "url": f"https://translation.googleapis.com/language/translate/v2/languages?key={key}",
                        "method": "GET",
                        "payload": None,
                    },
                ]
            )

            for test_case in test_cases:
                test_name = str(test_case["name"])
                url = str(test_case["url"])
                method = str(test_case["method"])
                payload_body = test_case.get("payload")
                http_code, payload, request_error = self._http_json_request(
                    url,
                    method=method,
                    payload=payload_body if isinstance(payload_body, dict) else None,
                )
                error_message = self.extract_google_error(payload, request_error)
                normalized_error = error_message.lower()

                if "api key" in normalized_error and "invalid" in normalized_error:
                    invalid_key = True
                if any(marker in normalized_error for marker in self.GOOGLE_RESTRICTION_MARKERS):
                    restriction_detected = True

                if test_name == "maps_geocoding":
                    api_status = str(payload.get("status", "")).upper() if isinstance(payload, dict) else ""
                    success = api_status in {"OK", "ZERO_RESULTS"}
                elif test_name == "youtube_data":
                    success = isinstance(payload, dict) and "error" not in payload and "kind" in payload
                elif test_name == "firebase_identitytoolkit_lookup":
                    firebase_markers = ("invalid_id_token", "missing_id_token", "user_not_found")
                    success = any(marker in normalized_error for marker in firebase_markers) or bool(
                        isinstance(payload, dict) and payload.get("users")
                    )
                elif test_name == "cloud_translate_languages":
                    success = (
                        isinstance(payload, dict)
                        and isinstance(payload.get("data"), dict)
                        and isinstance(payload.get("data", {}).get("languages"), list)
                    )
                else:
                    success = False

                if success:
                    accessible_apis.append(test_name)
                    successful_tests.append(
                        {
                            "name": test_name,
                            "url": url,
                            "method": method,
                            "request_payload": payload_body if isinstance(payload_body, dict) else None,
                            "response_payload": payload if isinstance(payload, dict) else {},
                            "http_code": http_code,
                        }
                    )

            vulnerable = False
            failed_checks: set[str] = set()
            if not invalid_key and accessible_apis:
                if not restriction_detected:
                    vulnerable = True
                    failed_checks.update({"restriction-controls", "quota-and-billing-abuse"})
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Missing Restriction Controls",
                            severity="high",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=restriction-controls "
                                f"CWE={restriction_meta['cwe']} CVE={restriction_meta['cve']} "
                                f"CVSS={restriction_meta['cvss']}"
                            ),
                        )
                    )
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Potential Quota/Billing Abuse",
                            severity="medium",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=quota-and-billing-abuse "
                                f"CWE={quota_meta['cwe']} CVE={quota_meta['cve']} "
                                f"CVSS={quota_meta['cvss']}"
                            ),
                        )
                    )

                if len(accessible_apis) > 1:
                    vulnerable = True
                    failed_checks.add("least-privilege-api-scope")
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Overly Broad API Scope",
                            severity="medium",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=least-privilege-api-scope "
                                f"CWE={scope_meta['cwe']} CVE={scope_meta['cve']} "
                                f"CVSS={scope_meta['cvss']}"
                            ),
                        )
                    )

            if not vulnerable:
                continue

            record = self._get_api_report_record(report_records, key)
            record["failed_checks"].update(failed_checks)
            record["accessible_apis"].update(accessible_apis)

            for test_result in successful_tests:
                self._append_unique(
                    record["tests"],
                    f"google-live-api-validation::{test_result['name']}",
                )

            if successful_tests:
                first_success = successful_tests[0]
                method = str(first_success["method"]).upper()
                url = str(first_success["url"])
                request_payload = first_success.get("request_payload")
                if method == "POST" and isinstance(request_payload, dict):
                    payload_preview = json.dumps(request_payload, ensure_ascii=True)
                    poc_cmd = (
                        f"curl -s -X POST \"{url}\" "
                        f"-H \"Content-Type: application/json\" -d '{payload_preview}'"
                    )
                else:
                    poc_cmd = f"curl -s \"{url}\""
                poc_response = self._json_preview(
                    first_success.get("response_payload", {}),
                    fallback=f"HTTP {first_success.get('http_code', 0)}",
                )
                if not record["poc_cmd"] or str(record["poc_cmd"]).startswith("grep -R"):
                    record["poc_cmd"] = poc_cmd
                    record["poc_response"] = poc_response

        return self._dedupe_findings(findings)

    def _assess_cloud_tokens(
        self,
        key_type: str,
        keys: dict[str, set[str]],
        endpoint: str,
        auth_header: str,
        success_predicate: Callable[[int, dict], bool],
        title: str,
        test_label: str,
        report_records: dict[str, dict],
    ) -> list[Finding]:
        findings: list[Finding] = []
        exposure_meta = self._api_key_check_meta("hardcoded-key-exposure")

        for key in sorted(keys):
            source_files = keys.get(key, set())
            masked_key = self.mask_secret(key)
            http_code, payload, request_error = self._http_json_request(
                endpoint,
                headers={"Authorization": f"{auth_header} {key}"},
            )
            error_message = self.extract_google_error(payload, request_error)
            is_vulnerable = success_predicate(http_code, payload)
            if not is_vulnerable:
                continue

            findings.append(
                Finding(
                    category="api_key_exposure",
                    title=title,
                    severity="high",
                    file="cloud_token_check",
                    evidence=(
                        f"key={masked_key} key_type={key_type} source_occurrences={len(source_files)} "
                        f"checklist=cloud-token-validation CWE={exposure_meta['cwe']} "
                        f"CVE={exposure_meta['cve']} CVSS={exposure_meta['cvss']}"
                    ),
                )
            )
            record = self._get_api_report_record(report_records, key)
            record["failed_checks"].add("cloud-token-validation")
            record["accessible_apis"].add(test_label)
            self._append_unique(record["tests"], test_label)

            poc_cmd = (
                f"curl -s \"{endpoint}\" "
                f"-H \"Authorization: {auth_header} {key}\""
            )
            poc_response = self._json_preview(
                payload,
                fallback=self.clean_line(error_message or f"HTTP {http_code}", max_len=220),
            )
            if not record["poc_cmd"] or str(record["poc_cmd"]).startswith("grep -R"):
                record["poc_cmd"] = poc_cmd
                record["poc_response"] = poc_response

        return findings

    def _assess_discovered_api_keys(self, hardcoded_findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        discovered_keys = self._extract_unique_api_keys(hardcoded_findings)
        if not discovered_keys:
            return [], []

        findings: list[Finding] = []
        report_records: dict[str, dict] = {}
        exposure_meta = self._api_key_check_meta("hardcoded-key-exposure")

        for key_type in sorted(discovered_keys):
            key_map = discovered_keys[key_type]
            for key_value in sorted(key_map):
                source_files = key_map[key_value]
                masked_key = self.mask_secret(key_value)
                severity = "medium" if key_type == "Generic API Key" else "high"
                findings.append(
                    Finding(
                        category="api_key_exposure",
                        title=f"{key_type} Hardcoded in Application Package",
                        severity=severity,
                        file="api_key_checklist",
                        evidence=(
                            f"key={masked_key} key_type={key_type} source_occurrences={len(source_files)} "
                            "checklist=hardcoded-key-exposure "
                            f"CWE={exposure_meta['cwe']} CVE={exposure_meta['cve']} "
                            f"CVSS={exposure_meta['cvss']}"
                        ),
                    )
                )
                record = self._get_api_report_record(report_records, key_value)
                record["failed_checks"].add("hardcoded-key-exposure")
                self._append_unique(
                    record["tests"],
                    "static-hardcoded-key-detection",
                )
                first_file = sorted(source_files)[0] if source_files else "source_file_unknown"
                source_preview = ", ".join(sorted(source_files)[:3]) if source_files else "none"
                record["poc_cmd"] = (
                    f"grep -R --line-number \"{key_value}\" \"{first_file}\""
                    if not record["poc_cmd"]
                    else record["poc_cmd"]
                )
                record["poc_response"] = (
                    f"key_type={key_type}; source_occurrences={len(source_files)}; "
                    f"sources={source_preview}"
                    if not record["poc_response"]
                    else record["poc_response"]
                )

        google_findings = self._assess_google_api_keys(
            discovered_keys.get("Google API Key", {}),
            report_records,
        )
        findings.extend(google_findings)

        github_findings = self._assess_cloud_tokens(
            key_type="GitHub Token",
            keys=discovered_keys.get("GitHub Token", {}),
            endpoint="https://api.github.com/user",
            auth_header="token",
            success_predicate=lambda code, payload: (
                code == 200 and isinstance(payload, dict) and bool(payload.get("login"))
            ),
            title="GitHub Token Grants Cloud API Access",
            test_label="github-user-api-validation",
            report_records=report_records,
        )
        findings.extend(github_findings)

        stripe_findings = self._assess_cloud_tokens(
            key_type="Stripe Live Key",
            keys=discovered_keys.get("Stripe Live Key", {}),
            endpoint="https://api.stripe.com/v1/account",
            auth_header="Bearer",
            success_predicate=lambda code, payload: (
                code == 200 and isinstance(payload, dict) and bool(payload.get("id"))
            ),
            title="Stripe Live Key Grants Cloud API Access",
            test_label="stripe-account-api-validation",
            report_records=report_records,
        )
        findings.extend(stripe_findings)
        report_lines = self._render_api_key_report_blocks(report_records)

        return self._dedupe_findings(findings), report_lines
