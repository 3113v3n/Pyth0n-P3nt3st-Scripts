"""Reusable helper functions for mobile static scanning."""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .models import Finding


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * (0.0 if p == 0 else math.log2(p))
    return entropy


def _severity_weight(cls, severity: str) -> int:
    return cls.SEVERITY_WEIGHTS.get(severity.lower(), 1)


def _is_valuable_url(cls, url: str) -> bool:
    cleaned = cls._sanitize_url_candidate(url)
    if not cleaned:
        return False
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https", "wss"}:
        return False
    host = (parsed.hostname or "").lower()
    if not cls._is_valid_url_host(host):
        return False
    if host in cls.URL_NOISE_HOSTS:
        return False
    if cls._is_source_repo_reference_url(host, parsed.path or ""):
        return False
    if cls.URL_PLACEHOLDER_RE.search(cleaned):
        return False
    if cls.URL_IGNORE_RE.search(cleaned):
        return False
    return True


def _canonicalize_url(cls, url: str) -> str:
    cleaned = cls._sanitize_url_candidate(url)
    if not cleaned:
        return ""
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    if not cls._is_valid_url_host(host):
        return ""
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or ""
    if path == "/":
        path = ""
    elif path:
        path = path.rstrip("/")
    return f"{parsed.scheme.lower()}://{netloc}{path}"


def _sanitize_url_candidate(cls, url: str) -> str:
    if not url:
        return ""
    cleaned = cls.URL_TRAILING_JUNK_RE.sub("", str(url).strip())
    if (
        not cleaned
        or "\\" in cleaned
        or cleaned.endswith("://")
        or cleaned.endswith("://.")
        or cleaned.endswith("://-")
    ):
        return ""
    return cleaned


def _is_valid_url_host(cls, host: str) -> bool:
    if not host:
        return False
    if cls.URL_PLACEHOLDER_RE.search(host):
        return False
    if host == "localhost":
        return True
    if cls.IPV4_EXACT_RE.fullmatch(host):
        return True
    return bool(cls.HOSTNAME_RE.fullmatch(host))


def _is_source_repo_reference_url(cls, host: str, path: str) -> bool:
    if host not in cls.REPO_REFERENCE_HOSTS:
        return False

    path_parts = [segment for segment in path.strip("/").split("/") if segment]
    if not path_parts:
        return False

    if host in {"github.com", "www.github.com"}:
        if len(path_parts) >= 3 and path_parts[2] in {
            "issues",
            "issue",
            "pull",
            "pulls",
            "blob",
            "tree",
            "commit",
            "commits",
            "compare",
            "wiki",
            "releases",
        }:
            return True
        return False

    if host == "gitlab.com":
        if len(path_parts) >= 4 and path_parts[2] == "-" and path_parts[3] in {
            "issues",
            "merge_requests",
            "blob",
            "tree",
            "commit",
            "commits",
            "releases",
        }:
            return True
        return False

    if host == "bitbucket.org":
        if len(path_parts) >= 3 and path_parts[2] in {
            "issues",
            "pull-requests",
            "src",
            "commits",
            "branches",
        }:
            return True
        return False

    return False


def _to_base_url(url: str) -> str:
    try:
        parsed = urlparse(str(url).strip())
    except ValueError:
        return ""

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return ""

    netloc = host
    default_ports = {"http": 80, "https": 443, "ws": 80, "wss": 443}
    if parsed.port and parsed.port != default_ports.get(scheme):
        netloc = f"{host}:{parsed.port}"
    return f"{scheme}://{netloc}"


def _collapse_urls_to_common_bases(cls, urls: set[str]) -> list[str]:
    unique_bases = {
        base
        for base in (cls._to_base_url(url) for url in urls)
        if base
    }
    return sorted(unique_bases)


def _snippet_at_index(text: str, index: int, radius: int = 50) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius)
    return text[start:end]


def _is_probable_version_ip(cls, ip_text: str, searchable_text: str, match_start: int) -> bool:
    try:
        parts = [int(part) for part in ip_text.split(".")]
    except ValueError:
        return False

    if len(parts) != 4:
        return False

    if ip_text in cls.KNOWN_PUBLIC_SERVICE_IPS:
        return False
    if parts[0] == 0:
        return True

    lowered = searchable_text.lower()
    ip_lower = ip_text.lower()
    snippet = cls._snippet_at_index(lowered, match_start, radius=60)
    if any(hint in snippet for hint in cls.OID_CONTEXT_HINTS):
        return True
    if any(hint in snippet for hint in cls.VERSION_CONTEXT_HINTS):
        return True
    if any(hint in snippet for hint in cls.NETWORK_CONTEXT_HINTS):
        return False
    if cls.IP_CONTEXT_RE.search(snippet):
        return False

    before = lowered[max(0, match_start - 16):match_start]
    if re.search(r"(?:\bversion\b|\bver\b)\s*$", before):
        return True
    if match_start > 0 and lowered[match_start - 1] in {"/", "v"}:
        return True

    match_end = match_start + len(ip_text)
    if match_end < len(lowered):
        trailing = lowered[match_end]
        if trailing in {"-", "_"} or trailing.isalnum():
            return True

    if all(part < 10 for part in parts) and ip_text not in cls.KNOWN_PUBLIC_SERVICE_IPS:
        return True
    if all(part <= 20 for part in parts):
        return True
    return bool(re.search(rf"{re.escape(ip_lower)}[a-z]", snippet))


def _is_valuable_secret_evidence(cls, title: str, evidence: str) -> bool:
    text = evidence.strip()
    lowered = text.lower()
    if len(text) < 10:
        return False

    if title in {"AWS Access Key", "Google API Key", "Stripe Live Key", "GitHub Token"}:
        return True

    if title == "JWT Token":
        return bool(
            re.search(
                r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
                text,
            )
        )

    if title == "Bearer/Auth Header Token":
        token_match = re.search(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)", text)
        if not token_match:
            return False
        token = token_match.group(1)
        return len(token) >= 20 and cls._entropy(token) >= 3.2

    value_match = cls.SECRET_VALUE_RE.search(text)
    if not value_match:
        return False
    value = value_match.group(1).strip()
    low_val = value.lower()
    if low_val in cls.NOISE_SECRET_VALUES:
        return False
    if value.startswith(("@string/", "@xml/", "BuildConfig.", "${", "#{")):
        return False
    if re.fullmatch(r"[0-9a-f]{6,}", low_val):
        return False
    if len(value) < 8:
        return False
    if cls._entropy(value) < 2.8 and not re.search(r"[A-Za-z].*[0-9]|[0-9].*[A-Za-z]", value):
        return False
    return True


def _extract_printable_strings(cls, data: bytes, max_strings: int) -> list[str]:
    strings: list[str] = []
    for idx, match in enumerate(cls.PRINTABLE_RE.finditer(data)):
        if idx >= max_strings:
            break
        token = match.group().decode("utf-8", errors="ignore").strip()
        if token:
            strings.append(token)
    return strings


def _read_text_if_possible(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _beautify_decoded_payload(payload: str) -> tuple[str, str]:
    text = str(payload)
    stripped = text.strip()
    if not stripped:
        return text, "text"

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, indent=2, ensure_ascii=False), "json"
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    if stripped.startswith("<") and stripped.endswith(">"):
        try:
            root = ET.fromstring(stripped)
            tree = ET.ElementTree(root)
            if hasattr(ET, "indent"):
                ET.indent(tree, space="  ")
            return ET.tostring(root, encoding="unicode"), "xml"
        except ET.ParseError:
            pass

    return text, "text"


def _decode_base64_if_interesting(cls, token: str) -> tuple[str, str] | None:
    if len(token) < 24:
        return None
    if len(set(token)) < 8:
        return None

    def decode_once(candidate: str) -> str | None:
        normalized = re.sub(r"\s+", "", candidate)
        if len(normalized) < 8:
            return None
        try:
            padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
        except (ValueError, base64.binascii.Error):
            return None
        if len(decoded_bytes) < 4 or len(decoded_bytes) > cls.MAX_BASE64_DECODE_BYTES:
            return None
        decoded_text_ = decoded_bytes.decode("utf-8", errors="ignore")
        if len(decoded_text_.strip()) < 4:
            return None
        if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in decoded_text_):
            return None
        return decoded_text_

    decoded_text = decode_once(token)
    if not decoded_text:
        return None

    for _ in range(cls.BASE64_MAX_DECODE_DEPTH - 1):
        candidate = re.sub(r"\s+", "", decoded_text)
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate or ""):
            break
        next_decoded = decode_once(candidate)
        if not next_decoded or next_decoded == decoded_text:
            break
        decoded_text = next_decoded

    analysis_text = decoded_text.strip()
    printable_ratio = sum(ch.isprintable() for ch in analysis_text) / max(len(analysis_text), 1)
    if printable_ratio < 0.9:
        return None
    ascii_ratio = sum(ord(ch) < 128 for ch in analysis_text) / max(len(analysis_text), 1)
    if ascii_ratio < 0.85:
        return None
    if not re.search(r"[A-Za-z]{4,}", analysis_text):
        return None
    if cls._entropy(analysis_text) < 2.6:
        return None

    lowered = analysis_text.lower()
    formatted_text, text_format = cls._beautify_decoded_payload(analysis_text)

    sensitive_markers = (
        "http://",
        "https://",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "bearer",
        "client_secret",
        "password",
        "private_key",
        "-----begin",
        "firebase",
        "googleapis",
        "jwt",
    )
    if any(marker in lowered for marker in sensitive_markers):
        return formatted_text, text_format

    try:
        parsed = json.loads(analysis_text)
        if isinstance(parsed, dict):
            keys = {str(k).lower() for k in parsed.keys()}
            interesting_keys = {
                "token", "access_token", "refresh_token", "secret", "api_key",
                "apikey", "password", "client_secret", "private_key",
            }
            if keys & interesting_keys:
                return formatted_text, text_format
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return None


def _build_base64_entry(rel_file: str, encoded_token: str, decoded_text: str, decoded_format: str) -> dict:
    return {
        "file": rel_file,
        "format": decoded_format or "text",
        "encoded": encoded_token,
        "decoded": decoded_text,
    }


def _snippet_around(text: str, needle: str, radius: int = 80) -> str:
    index = text.find(needle)
    if index < 0:
        return needle
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return " ".join(text[start:end].split())


def _normalize_line_no_truncate(text: str) -> str:
    return " ".join(str(text).strip().split())


def _scan_text_for_indicators(self, text: str, rel_file: str) -> tuple[list[Finding], list[Finding]]:
    lowered = text.lower()
    risks: list[Finding] = []
    controls: list[Finding] = []

    for category, title, severity, needles in self.RISK_INDICATORS:
        for needle in needles:
            n = needle.lower()
            if n in lowered:
                risks.append(
                    Finding(
                        category=category,
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=self.clean_line(self._snippet_around(lowered, n)),
                    )
                )
                break

    for category, title, severity, pattern in self.ADVANCED_RISK_REGEX:
        match = pattern.search(text)
        if match:
            snippet = self.clean_line(self._snippet_around(text, match.group(0)))
            risks.append(
                Finding(
                    category=category,
                    title=title,
                    severity=severity,
                    file=rel_file,
                    evidence=snippet,
                )
            )

    for category, title, severity, needles in self.CONTROL_INDICATORS:
        for needle in needles:
            n = needle.lower()
            if n in lowered:
                controls.append(
                    Finding(
                        category=category,
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=self.clean_line(self._snippet_around(lowered, n)),
                    )
                )
                break

    return risks, controls


def _scan_single_file(self, file_path: Path, root: Path) -> dict:
    rel_file = self._safe_relpath(file_path, root)
    suffix = file_path.suffix.lower()

    result = {
        "file": rel_file,
        "urls": set(),
        "ips": set(),
        "hardcoded": [],
        "base64": [],
        "risk_findings": [],
        "control_findings": [],
        "bytes_scanned": 0,
        "skipped": False,
    }

    try:
        stat = file_path.stat()
    except OSError:
        result["skipped"] = True
        return result

    if suffix in self.BINARY_SKIP_EXTENSIONS and stat.st_size > self.MAX_FILE_SIZE_BYTES:
        result["skipped"] = True
        return result

    if stat.st_size > self.MAX_FILE_SIZE_BYTES:
        result["skipped"] = True
        return result

    try:
        data = file_path.read_bytes()
    except OSError:
        result["skipped"] = True
        return result

    result["bytes_scanned"] = len(data)

    text_parts: list[str] = []
    decoded_text = ""
    if suffix in self.TEXT_EXTENSIONS:
        try:
            decoded_text = data.decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""
        if decoded_text:
            text_parts.append(decoded_text)

    if not decoded_text:
        printable = self._extract_printable_strings(data, self.MAX_STRINGS_PER_FILE)
        if printable:
            text_parts.append("\n".join(printable))

    if not text_parts:
        return result

    searchable = "\n".join(text_parts)
    if len(searchable) > self.MAX_TEXT_CHARS_PER_FILE:
        searchable = searchable[: self.MAX_TEXT_CHARS_PER_FILE]

    for match in self.URL_RE.findall(searchable):
        if self._is_valuable_url(match):
            canonical_url = self._canonicalize_url(match)
            if canonical_url:
                result["urls"].add(canonical_url)

    for match_obj in self.IP_RE.finditer(searchable):
        match = match_obj.group(0)
        try:
            ip_obj = ipaddress.ip_address(match)
            if (
                not ip_obj.is_loopback
                and not ip_obj.is_multicast
                and not ip_obj.is_unspecified
                and not ip_obj.is_reserved
            ):
                if self._is_probable_version_ip(match, searchable, match_obj.start()):
                    continue
                result["ips"].add(match)
        except ValueError:
            continue

    for title, severity, pattern in self.SECRET_PATTERNS:
        for m in pattern.finditer(searchable):
            evidence = self._normalize_line_no_truncate(m.group(0))
            if not self._is_valuable_secret_evidence(title, evidence):
                continue
            result["hardcoded"].append(
                Finding(
                    category="hardcoded_secret",
                    title=title,
                    severity=severity,
                    file=rel_file,
                    evidence=evidence,
                )
            )

    seen_b64 = set()
    for token in self.BASE64_TOKEN_RE.findall(searchable):
        if token in seen_b64:
            continue
        seen_b64.add(token)
        decoded_payload = self._decode_base64_if_interesting(token)
        if decoded_payload:
            decoded_text, decoded_format = decoded_payload
            result["base64"].append(
                self._build_base64_entry(rel_file, token, decoded_text, decoded_format)
            )

    for url in result["urls"]:
        if url.lower().startswith("http://"):
            result["risk_findings"].append(
                Finding(
                    category="network_security",
                    title="Potential Cleartext Backend Endpoint",
                    severity="medium",
                    file=rel_file,
                    evidence=self._normalize_line_no_truncate(url),
                )
            )

    risks, controls = self._scan_text_for_indicators(searchable, rel_file)
    result["risk_findings"].extend(risks)
    result["control_findings"].extend(controls)

    return result


def _scan_android_manifest(self, root: Path) -> tuple[list[Finding], list[Finding]]:
    manifest = root / "AndroidManifest.xml"
    if not manifest.exists():
        return [], []

    text = self._read_text_if_possible(manifest)
    if not text:
        return [], []

    rel = self._safe_relpath(manifest, root)
    risks: list[Finding] = []
    controls: list[Finding] = []

    if 'android:debuggable="true"' in text:
        risks.append(
            Finding(
                "debugging",
                "Manifest Debuggable Enabled",
                "high",
                rel,
                'android:debuggable="true"',
            )
        )
    if 'android:allowBackup="true"' in text:
        risks.append(
            Finding(
                "backup",
                "Manifest Backup Enabled",
                "medium",
                rel,
                'android:allowBackup="true"',
            )
        )
    if 'android:usesCleartextTraffic="true"' in text:
        risks.append(
            Finding(
                "network_security",
                "Manifest Cleartext Traffic Enabled",
                "high",
                rel,
                'android:usesCleartextTraffic="true"',
            )
        )

    exported_pattern = re.compile(
        r"<(activity|service|receiver|provider)\b[^>]*android:exported=\"true\"[^>]*>",
        re.IGNORECASE,
    )
    for m in exported_pattern.finditer(text):
        snippet = self._normalize_line_no_truncate(m.group(0))
        sev = "high" if "android:permission" not in snippet.lower() else "medium"
        title = "Exported Component Without Permission" if sev == "high" else "Exported Component"
        risks.append(Finding("component_exposure", title, sev, rel, snippet))

    if "android:networkSecurityConfig=" in text:
        controls.append(
            Finding(
                "pinning",
                "Network Security Config Declared",
                "info",
                rel,
                "android:networkSecurityConfig",
            )
        )

    return risks, controls


def _scan_ios_plist(self, root: Path) -> tuple[list[Finding], list[Finding]]:
    plist_candidates = [p for p in root.rglob("Info.plist") if p.is_file()]
    if not plist_candidates:
        return [], []

    risks: list[Finding] = []
    controls: list[Finding] = []

    for plist_path in plist_candidates[:3]:
        rel = self._safe_relpath(plist_path, root)
        try:
            payload = plistlib.loads(plist_path.read_bytes())
        except Exception:
            text = self._read_text_if_possible(plist_path)
            if "NSAllowsArbitraryLoads" in text:
                risks.append(
                    Finding(
                        "network_security",
                        "ATS Arbitrary Loads Detected",
                        "high",
                        rel,
                        "NSAllowsArbitraryLoads",
                    )
                )
            continue

        ats = payload.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            if bool(ats.get("NSAllowsArbitraryLoads")):
                risks.append(
                    Finding(
                        "network_security",
                        "ATS Arbitrary Loads Enabled",
                        "high",
                        rel,
                        "NSAllowsArbitraryLoads=true",
                    )
                )
            else:
                controls.append(
                    Finding(
                        "network_security",
                        "ATS Policy Present",
                        "info",
                        rel,
                        "NSAppTransportSecurity present",
                    )
                )

        url_types = payload.get("CFBundleURLTypes")
        if url_types:
            controls.append(
                Finding(
                    "deeplink",
                    "Custom URL Schemes Declared",
                    "info",
                    rel,
                    "CFBundleURLTypes present",
                )
            )

    return risks, controls


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique = {}
    for finding in findings:
        key = (finding.category, finding.title, finding.severity, finding.file, finding.evidence)
        unique[key] = finding
    return list(unique.values())


def _build_severity_score(cls, findings: list[Finding]) -> dict:
    severity_counts: dict[str, int] = {key: 0 for key in cls.SEVERITY_WEIGHTS}
    weighted_total = 0

    for finding in findings:
        sev = finding.severity.lower()
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1
        weighted_total += cls._severity_weight(sev)

    risk_score = min(100, int(round(weighted_total * 2.5)))
    security_posture_score = max(0, 100 - risk_score)

    if risk_score >= 85:
        risk_band = "critical"
    elif risk_score >= 65:
        risk_band = "high"
    elif risk_score >= 40:
        risk_band = "medium"
    elif risk_score >= 20:
        risk_band = "low"
    else:
        risk_band = "informational"

    return {
        "risk_score": risk_score,
        "security_posture_score": security_posture_score,
        "risk_band": risk_band,
        "weighted_total": weighted_total,
        "severity_breakdown": severity_counts,
    }
