"""Android resource helper functions extracted from mobile static scan helpers."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding


def parse_android_resource_id_literal(token: str) -> int | None:
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



def register_symbol_id(symbol_map: dict[str, set[int]], symbol: str, resource_id: int) -> None:
    key = str(symbol or "").strip()
    if not key:
        return
    symbol_map.setdefault(key, set()).add(resource_id)



def build_android_obfuscated_maps(
    constants,
    root: Path,
    *,
    safe_relpath,
    parse_resource_id,
    read_text,
    register_symbol_id,
) -> tuple[dict[int, dict], dict[str, set[int]]]:
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
                string_sources[name] = safe_relpath(strings_file, root)

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
            resource_id = parse_resource_id(node.attrib.get("id", ""))
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
                "source": string_sources.get(name, safe_relpath(public_file, root)),
            }

    if string_values:
        r_symbol_files = set(root.rglob("R$*.smali")) | set(root.rglob("R$*.java")) | set(root.rglob("R.java"))
        for symbol_file in sorted(r_symbol_files):
            text = read_text(symbol_file)
            if not text:
                continue
            for pattern in (constants.JAVA_STATIC_INT_ASSIGN_RE, constants.SMALI_STATIC_INT_ASSIGN_RE):
                for match in pattern.finditer(text):
                    symbol = match.group(1)
                    resource_id = parse_resource_id(match.group(2))
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
                        "source": string_sources.get(symbol, safe_relpath(symbol_file, root)),
                    }

    symbol_map: dict[str, set[int]] = {}
    code_suffixes = {".java", ".kt", ".smali"}
    for code_file in root.rglob("*"):
        if not code_file.is_file() or code_file.suffix.lower() not in code_suffixes:
            continue
        text = read_text(code_file)
        if not text:
            continue

        class_name = ""
        if code_file.suffix.lower() == ".smali":
            class_match = constants.SMALI_CLASS_RE.search(text)
            if class_match:
                class_name = class_match.group(1).split("/")[-1]
            assignment_pattern = constants.SMALI_STATIC_INT_ASSIGN_RE
        else:
            class_match = constants.JAVA_CLASS_RE.search(text)
            if class_match:
                class_name = class_match.group(1)
            assignment_pattern = constants.JAVA_STATIC_INT_ASSIGN_RE

        for match in assignment_pattern.finditer(text):
            symbol = match.group(1)
            resource_id = parse_resource_id(match.group(2))
            if resource_id is None or resource_id not in resource_map:
                continue
            register_symbol_id(symbol_map, symbol, resource_id)
            if class_name:
                register_symbol_id(symbol_map, f"{class_name}.{symbol}", resource_id)

    return resource_map, symbol_map



def is_sensitive_obfuscated_resource_value(constants, resource_name: str, resource_value: str) -> bool:
    value = " ".join(str(resource_value or "").split())
    if not value:
        return False

    lower_value = value.lower()
    lower_name = str(resource_name or "").strip().lower()
    if lower_value in constants.NOISE_SECRET_VALUES:
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
        and constants._entropy(value) >= 3.6
        and re.search(r"[A-Za-z]", value)
        and re.search(r"[0-9]", value)
    ):
        return True
    return False



def scan_obfuscated_resource_references(
    constants,
    text: str,
    rel_file: str,
    resource_map: dict[int, dict],
    symbol_map: dict[str, set[int]] | None = None,
) -> tuple[list[dict], list[Finding]]:
    if not resource_map:
        return [], []

    symbol_map = symbol_map or {}
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

    for literal in constants.ANDROID_INT_LITERAL_RE.findall(text):
        resource_id = constants._parse_android_resource_id_literal(literal)
        if resource_id is None:
            continue
        add_reference(resource_id, literal)

    if symbol_map:
        for match in constants.QUALIFIED_SYMBOL_RE.finditer(text):
            token = match.group(1)
            for symbol_key in (token, token.split(".", 1)[-1]):
                for resource_id in symbol_map.get(symbol_key, set()):
                    add_reference(resource_id, token)

        for match in constants.SMALI_FIELD_REF_RE.finditer(text):
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
        if not constants._is_sensitive_obfuscated_resource_value(name, value):
            continue

        value_summary = constants._normalize_line_no_truncate(value.replace("\n", "\\n"))
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
