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


def _is_noise_base64_context(cls, context_window: str) -> bool:
    """Reject obvious base64 noise contexts (images/fonts/media/binary data URIs)."""
    context = str(context_window or "")
    return bool(cls.BASE64_DATA_URI_PREFIX_RE.search(context))


def _decode_base64_if_interesting(
    cls,
    token: str,
    *,
    context_window: str = "",
) -> tuple[str, str] | None:
    if len(token) < 24:
        return None
    if len(set(token)) < 8:
        return None
    if cls._is_noise_base64_context(context_window):
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
    has_sensitive_marker = any(marker in lowered for marker in sensitive_markers)

    # Skip high-volume graphic/vector payloads (common in app bundles) unless they
    # still contain explicit sensitive markers.
    if not has_sensitive_marker:
        if "<svg" in lowered or "http://www.w3.org/2000/svg" in lowered:
            return None
        if lowered.startswith("<?xml") and "<svg" in lowered:
            return None
        if any(tag in lowered for tag in ("<path", "<rect", "<circle", "<polygon")) and "<svg" in lowered:
            return None

    if len(analysis_text) > 20_000 and not has_sensitive_marker:
        return None

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


def _parse_android_resource_id_literal(token: str) -> int | None:
    raw = str(token or "").strip().rstrip(",;)")
    if not raw:
        return None
    try:
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError:
        return None
    if value <= 0 or value > 0xFFFFFFFF:
        return None
    return value


def _register_symbol_id(symbol_map: dict[str, set[int]], symbol: str, resource_id: int) -> None:
    key = str(symbol or "").strip()
    if not key:
        return
    symbol_map.setdefault(key, set()).add(resource_id)


def _build_android_obfuscated_maps(self, root: Path) -> tuple[dict[int, dict], dict[str, set[int]]]:
    res_root = root / "res"
    if not res_root.exists():
        return {}, {}

    string_values: dict[str, str] = {}
    string_sources: dict[str, str] = {}
    for strings_file in sorted(
        (path for path in res_root.glob("values*/strings*.xml") if path.is_file()),
        key=lambda p: (0 if p.parent.name == "values" else 1, p.parent.name, p.name),
    ):
        try:
            resources = ET.fromstring(strings_file.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ET.ParseError):
            continue
        is_default_values_file = strings_file.parent.name == "values"
        for node in resources.findall("string"):
            name = str(node.attrib.get("name", "")).strip()
            if not name:
                continue
            value = "".join(node.itertext()).strip()
            if not value:
                continue
            if name not in string_values or is_default_values_file:
                string_values[name] = value
                string_sources[name] = self._safe_relpath(strings_file, root)

    resource_map: dict[int, dict] = {}
    for public_file in sorted(
        (path for path in res_root.glob("values*/public.xml") if path.is_file()),
        key=lambda p: (0 if p.parent.name == "values" else 1, p.parent.name, p.name),
    ):
        try:
            resources = ET.fromstring(public_file.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ET.ParseError):
            continue
        for node in resources.findall("public"):
            if str(node.attrib.get("type", "")).strip().lower() != "string":
                continue
            name = str(node.attrib.get("name", "")).strip()
            resource_id = self._parse_android_resource_id_literal(node.attrib.get("id", ""))
            if not name or resource_id is None:
                continue
            value = string_values.get(name)
            if not value:
                continue
            resource_map[resource_id] = {
                "id": resource_id,
                "hex": f"0x{resource_id:08x}",
                "name": name,
                "value": value,
                "source": string_sources.get(name, self._safe_relpath(public_file, root)),
            }

    # Fallback mapping when public.xml is unavailable or incomplete.
    if string_values:
        r_symbol_files = set(root.rglob("R$*.smali")) | set(root.rglob("R$*.java")) | set(root.rglob("R.java"))
        for symbol_file in sorted(r_symbol_files):
            text = _read_text_if_possible(symbol_file)
            if not text:
                continue
            for pattern in (self.JAVA_STATIC_INT_ASSIGN_RE, self.SMALI_STATIC_INT_ASSIGN_RE):
                for match in pattern.finditer(text):
                    symbol = match.group(1)
                    resource_id = self._parse_android_resource_id_literal(match.group(2))
                    if resource_id is None or resource_id in resource_map:
                        continue
                    value = string_values.get(symbol)
                    if not value:
                        continue
                    resource_map[resource_id] = {
                        "id": resource_id,
                        "hex": f"0x{resource_id:08x}",
                        "name": symbol,
                        "value": value,
                        "source": string_sources.get(symbol, self._safe_relpath(symbol_file, root)),
                    }

    symbol_map: dict[str, set[int]] = {}
    code_suffixes = {".java", ".kt", ".smali"}
    for code_file in root.rglob("*"):
        if not code_file.is_file() or code_file.suffix.lower() not in code_suffixes:
            continue
        text = _read_text_if_possible(code_file)
        if not text:
            continue

        class_name = ""
        if code_file.suffix.lower() == ".smali":
            class_match = self.SMALI_CLASS_RE.search(text)
            if class_match:
                class_name = class_match.group(1).split("/")[-1]
            assignment_pattern = self.SMALI_STATIC_INT_ASSIGN_RE
        else:
            class_match = self.JAVA_CLASS_RE.search(text)
            if class_match:
                class_name = class_match.group(1)
            assignment_pattern = self.JAVA_STATIC_INT_ASSIGN_RE

        for match in assignment_pattern.finditer(text):
            symbol = match.group(1)
            resource_id = self._parse_android_resource_id_literal(match.group(2))
            if resource_id is None or resource_id not in resource_map:
                continue
            self._register_symbol_id(symbol_map, symbol, resource_id)
            if class_name:
                self._register_symbol_id(symbol_map, f"{class_name}.{symbol}", resource_id)

    return resource_map, symbol_map


def _is_sensitive_obfuscated_resource_value(cls, resource_name: str, resource_value: str) -> bool:
    value = " ".join(str(resource_value or "").split())
    if not value:
        return False

    lower_value = value.lower()
    lower_name = str(resource_name or "").strip().lower()
    if lower_value in cls.NOISE_SECRET_VALUES:
        return False
    if lower_value.startswith(("@string/", "@xml/")):
        return False

    direct_secret_patterns = (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        re.compile(
            r"(?i)\b(?:api[_-]?key|token|secret|client[_-]?secret|access[_-]?key)\b\s*(?:[:=]|=>)\s*['\"][^'\"]{8,}['\"]"
        ),
    )
    if any(pattern.search(value) for pattern in direct_secret_patterns):
        return True

    if re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", value):
        return bool(
            re.search(
                r"(?i)(?:api[_-]?key|token|secret|client[_-]?secret|access[_-]?key)=",
                value,
            )
        )

    if " " in value:
        return False

    strong_keywords = (
        "access_key",
        "apikey",
        "api_key",
        "bearer",
        "client_secret",
        "jwt",
        "private_key",
        "refresh_token",
        "secret",
        "signing",
        "token",
    )
    if any(keyword in lower_value or keyword in lower_name for keyword in strong_keywords):
        if len(value) >= 8:
            return True

    if (
        len(value) >= 24
        and cls._entropy(value) >= 3.6
        and re.search(r"[A-Za-z]", value)
        and re.search(r"[0-9]", value)
    ):
        return True
    return False


def _scan_obfuscated_resource_references(self, text: str, rel_file: str) -> tuple[list[dict], list[Finding]]:
    resource_map = getattr(self, "_android_obfuscated_resource_map", {}) or {}
    if not resource_map:
        return [], []

    symbol_map = getattr(self, "_android_obfuscated_symbol_map", {}) or {}
    references: list[dict] = []
    findings: list[Finding] = []
    seen_ref_keys: set[tuple[int, str]] = set()
    refs_by_id: dict[int, set[str]] = {}

    def add_reference(resource_id: int, token: str) -> None:
        entry = resource_map.get(resource_id)
        if not entry:
            return
        ref_key = (resource_id, token)
        if ref_key in seen_ref_keys:
            return
        seen_ref_keys.add(ref_key)
        refs_by_id.setdefault(resource_id, set()).add(token)
        references.append(
            {
                "id": resource_id,
                "hex": entry.get("hex", f"0x{resource_id:08x}"),
                "resource": entry.get("name", ""),
                "value": entry.get("value", ""),
                "file": rel_file,
                "token": token,
            }
        )

    for literal in self.ANDROID_INT_LITERAL_RE.findall(text):
        resource_id = self._parse_android_resource_id_literal(literal)
        if resource_id is None:
            continue
        add_reference(resource_id, literal)

    if symbol_map:
        for match in self.QUALIFIED_SYMBOL_RE.finditer(text):
            token = match.group(1)
            for symbol_key in (token, token.split(".", 1)[-1]):
                for resource_id in symbol_map.get(symbol_key, set()):
                    add_reference(resource_id, token)

        for match in self.SMALI_FIELD_REF_RE.finditer(text):
            class_simple = match.group(1).split("/")[-1]
            field_name = match.group(2)
            token = f"{class_simple}.{field_name}"
            for symbol_key in (token, field_name):
                for resource_id in symbol_map.get(symbol_key, set()):
                    add_reference(resource_id, token)

    high_signal_markers = (
        "secret",
        "token",
        "apikey",
        "api_key",
        "client_secret",
        "access_key",
        "private",
        "bearer",
        "jwt",
    )
    for resource_id, tokens in refs_by_id.items():
        entry = resource_map.get(resource_id, {})
        value = str(entry.get("value", "")).strip()
        name = str(entry.get("name", "")).strip()
        if not self._is_sensitive_obfuscated_resource_value(name, value):
            continue

        value_summary = self._normalize_line_no_truncate(value.replace("\n", "\\n"))
        if len(value_summary) > 220:
            value_summary = f"{value_summary[:217]}..."
        combined_lower = f"{name.lower()} {value.lower()}"
        severity = "high" if any(marker in combined_lower for marker in high_signal_markers) else "medium"
        tokens_summary = ", ".join(sorted(tokens)[:4])
        if len(tokens) > 4:
            tokens_summary = f"{tokens_summary}, ..."
        findings.append(
            Finding(
                category="hardcoded_secret",
                title="Obfuscated Resource ID Decodes to Sensitive String",
                severity=severity,
                file=rel_file,
                evidence=(
                    f"id={resource_id} hex={entry.get('hex', f'0x{resource_id:08x}')} "
                    f"resource={name or '<unknown>'} value=\"{value_summary}\" refs={tokens_summary}"
                ),
            )
        )

    return references, findings


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
        "obfuscated_refs": [],
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

    obfuscated_refs, obfuscated_findings = self._scan_obfuscated_resource_references(searchable, rel_file)
    if obfuscated_refs:
        result["obfuscated_refs"].extend(obfuscated_refs)
    if obfuscated_findings:
        result["hardcoded"].extend(obfuscated_findings)

    seen_b64 = set()
    for token_match in self.BASE64_TOKEN_RE.finditer(searchable):
        token = token_match.group(0)
        if token in seen_b64:
            continue
        seen_b64.add(token)
        context_start = max(0, token_match.start() - 160)
        context_end = min(len(searchable), token_match.end() + 32)
        context_window = searchable[context_start:context_end]
        decoded_payload = self._decode_base64_if_interesting(
            token,
            context_window=context_window,
        )
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
    if 'android:requestLegacyExternalStorage="true"' in text:
        risks.append(
            Finding(
                "storage",
                "Legacy External Storage Access Requested",
                "medium",
                rel,
                'android:requestLegacyExternalStorage="true"',
            )
        )

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

    try:
        manifest_xml = ET.fromstring(text)
    except ET.ParseError:
        return risks, controls

    android_ns = "{http://schemas.android.com/apk/res/android}"

    def attr(element: ET.Element, key: str) -> str:
        return str(
            element.get(f"{android_ns}{key}")
            or element.get(f"android:{key}")
            or ""
        ).strip()

    uses_sdk = manifest_xml.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = attr(uses_sdk, "minSdkVersion")
        target_sdk = attr(uses_sdk, "targetSdkVersion")
        if min_sdk.isdigit() and int(min_sdk) < 24:
            risks.append(
                Finding(
                    "platform_hardening",
                    "Manifest Minimum SDK Supports Legacy Android Versions",
                    "medium",
                    rel,
                    f"minSdkVersion={min_sdk}",
                )
            )
        if target_sdk.isdigit() and int(target_sdk) < 31:
            risks.append(
                Finding(
                    "platform_hardening",
                    "Manifest Target SDK Is Outdated",
                    "medium",
                    rel,
                    f"targetSdkVersion={target_sdk}",
                )
            )

    for permission in manifest_xml.findall("uses-permission"):
        name = attr(permission, "name")
        if name in self.DANGEROUS_ANDROID_PERMISSIONS:
            risks.append(
                Finding(
                    "permission_model",
                    "Sensitive Permission Requested",
                    "low",
                    rel,
                    name,
                )
            )

    application_node = manifest_xml.find("application")
    if application_node is None:
        return risks, controls

    full_backup = attr(application_node, "fullBackupContent")
    data_extraction_rules = attr(application_node, "dataExtractionRules")
    if full_backup or data_extraction_rules:
        controls.append(
            Finding(
                "backup",
                "Backup/Data Extraction Rules Declared",
                "info",
                rel,
                ", ".join(
                    value
                    for value in [
                        f"fullBackupContent={full_backup}" if full_backup else "",
                        f"dataExtractionRules={data_extraction_rules}" if data_extraction_rules else "",
                    ]
                    if value
                ),
            )
        )

    network_config_ref = attr(application_node, "networkSecurityConfig")
    if network_config_ref.startswith("@xml/"):
        config_name = network_config_ref.split("/", 1)[1]
        config_path = root / "res" / "xml" / f"{config_name}.xml"
        if config_path.exists():
            config_text = self._read_text_if_possible(config_path)
            config_rel = self._safe_relpath(config_path, root)
            if 'cleartextTrafficPermitted="true"' in config_text:
                risks.append(
                    Finding(
                        "network_security",
                        "Network Security Config Allows Cleartext Traffic",
                        "high",
                        config_rel,
                        'cleartextTrafficPermitted="true"',
                    )
                )
            if 'src="user"' in config_text:
                risks.append(
                    Finding(
                        "network_security",
                        "Network Security Config Trusts User-Added CAs",
                        "medium",
                        config_rel,
                        'certificates src="user"',
                    )
                )
            if "<pin-set" in config_text:
                controls.append(
                    Finding(
                        "pinning",
                        "Certificate Pinset Declared in Network Security Config",
                        "info",
                        config_rel,
                        "pin-set",
                    )
                )

    component_tags = ("activity", "service", "receiver", "provider")
    for tag in component_tags:
        for component in application_node.findall(tag):
            exported = attr(component, "exported").lower()
            permission = (
                attr(component, "permission")
                or attr(component, "readPermission")
                or attr(component, "writePermission")
            )
            has_intent_filter = bool(component.findall("intent-filter"))
            is_exposed = exported == "true" or (not exported and has_intent_filter)
            if is_exposed:
                comp_name = attr(component, "name") or "<unnamed>"
                evidence = f"{tag}={comp_name} exported={exported or 'implicit'}"
                if permission:
                    evidence = f"{evidence} permission={permission}"
                sev = "high" if not permission else "medium"
                title = "Exported Component Without Permission" if not permission else "Exported Component"
                risks.append(Finding("component_exposure", title, sev, rel, evidence))

            if tag == "activity":
                task_affinity = attr(component, "taskAffinity")
                allow_task_reparenting = attr(component, "allowTaskReparenting").lower() == "true"
                if task_affinity and allow_task_reparenting:
                    risks.append(
                        Finding(
                            "task_hijacking",
                            "Activity Task Affinity + Reparenting Enabled",
                            "medium",
                            rel,
                            f"activity={attr(component, 'name') or '<unnamed>'} taskAffinity={task_affinity}",
                        )
                    )

            for intent_filter in component.findall("intent-filter"):
                action_names = {
                    attr(action, "name")
                    for action in intent_filter.findall("action")
                    if attr(action, "name")
                }
                category_names = {
                    attr(category, "name")
                    for category in intent_filter.findall("category")
                    if attr(category, "name")
                }
                schemes = {
                    attr(data_node, "scheme").lower()
                    for data_node in intent_filter.findall("data")
                    if attr(data_node, "scheme")
                }
                has_http_scheme = bool({"http", "https"} & schemes)
                is_view_browsable = (
                    "android.intent.action.VIEW" in action_names
                    and "android.intent.category.BROWSABLE" in category_names
                )
                if is_view_browsable and has_http_scheme:
                    auto_verify = attr(intent_filter, "autoVerify").lower()
                    if auto_verify != "true":
                        risks.append(
                            Finding(
                                "deeplink",
                                "App Links Missing autoVerify",
                                "medium",
                                rel,
                                f"activity={attr(component, 'name') or '<unnamed>'} schemes={','.join(sorted(schemes))}",
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

            if bool(ats.get("NSAllowsArbitraryLoadsInWebContent")):
                risks.append(
                    Finding(
                        "network_security",
                        "ATS Allows Arbitrary Loads in Web Content",
                        "medium",
                        rel,
                        "NSAllowsArbitraryLoadsInWebContent=true",
                    )
                )

            exception_domains = ats.get("NSExceptionDomains", {})
            if isinstance(exception_domains, dict):
                for domain, cfg in exception_domains.items():
                    if not isinstance(cfg, dict):
                        continue
                    if bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads")):
                        risks.append(
                            Finding(
                                "network_security",
                                "ATS Exception Domain Allows Insecure HTTP",
                                "high",
                                rel,
                                f"domain={domain} NSExceptionAllowsInsecureHTTPLoads=true",
                            )
                        )
                    if bool(cfg.get("NSIncludesSubdomains")):
                        controls.append(
                            Finding(
                                "network_security",
                                "ATS Exception Domain Includes Subdomains",
                                "info",
                                rel,
                                f"domain={domain} NSIncludesSubdomains=true",
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

        if bool(payload.get("UIFileSharingEnabled")):
            risks.append(
                Finding(
                    "storage",
                    "iOS File Sharing Enabled",
                    "medium",
                    rel,
                    "UIFileSharingEnabled=true",
                )
            )

        if bool(payload.get("LSSupportsOpeningDocumentsInPlace")):
            risks.append(
                Finding(
                    "storage",
                    "Documents Open-In-Place Enabled",
                    "low",
                    rel,
                    "LSSupportsOpeningDocumentsInPlace=true",
                )
            )

        queried_schemes = payload.get("LSApplicationQueriesSchemes")
        if isinstance(queried_schemes, list) and queried_schemes:
            controls.append(
                Finding(
                    "privacy",
                    "Queried URL Schemes Declared",
                    "info",
                    rel,
                    f"LSApplicationQueriesSchemes count={len(queried_schemes)}",
                )
            )

    entitlement_candidates = [p for p in root.rglob("*.entitlements") if p.is_file()]
    for ent_path in entitlement_candidates[:5]:
        ent_rel = self._safe_relpath(ent_path, root)
        try:
            ent_payload = plistlib.loads(ent_path.read_bytes())
        except Exception:
            continue

        if bool(ent_payload.get("get-task-allow")):
            risks.append(
                Finding(
                    "debugging",
                    "Debug Entitlement Enabled",
                    "high",
                    ent_rel,
                    "get-task-allow=true",
                )
            )

        if "com.apple.security.application-groups" in ent_payload:
            controls.append(
                Finding(
                    "storage",
                    "Application Groups Entitlement Present",
                    "info",
                    ent_rel,
                    "com.apple.security.application-groups",
                )
            )

        if "keychain-access-groups" in ent_payload:
            controls.append(
                Finding(
                    "secure_storage",
                    "Keychain Access Groups Entitlement Present",
                    "info",
                    ent_rel,
                    "keychain-access-groups",
                )
            )

    return risks, controls


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique = {}
    for finding in findings:
        key = (finding.category, finding.title, finding.severity, finding.file, finding.evidence)
        unique[key] = finding
    ordered_keys = sorted(
        unique,
        key=lambda item: (
            str(item[2]).lower(),
            str(item[0]).lower(),
            str(item[1]).lower(),
            str(item[3]).lower(),
            str(item[4]).lower(),
        ),
    )
    return [unique[key] for key in ordered_keys]


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
