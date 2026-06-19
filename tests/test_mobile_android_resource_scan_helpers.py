import re


def _constants():
    class Constants:
        ANDROID_INT_LITERAL_RE = re.compile(r"(?<![\w$])(0x[0-9a-fA-F]{6,10}|\d{8,10})(?![\w$])")
        QUALIFIED_SYMBOL_RE = re.compile(r"\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\b")
        SMALI_FIELD_REF_RE = re.compile(r"L([^;]+);->([A-Za-z_$][\w$]*)\s*:\s*I")

        @staticmethod
        def _normalize_line_no_truncate(text: str) -> str:
            return " ".join(str(text).strip().split())

        @staticmethod
        def _is_sensitive_obfuscated_resource_value(name: str, value: str) -> bool:
            return "secret" in name.lower() or "secret" in value.lower() or "token" in value.lower()

        @staticmethod
        def _parse_android_resource_id_literal(token: str) -> int | None:
            raw = str(token or "").strip().rstrip(",;)")
            if not raw:
                return None
            try:
                return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
            except ValueError:
                return None

    return Constants


def test_scan_obfuscated_resource_references_returns_references_and_finding():
    from utils.mobile.android_resource_helpers import scan_obfuscated_resource_references

    constants = _constants()
    resource_map = {
        0x7F110001: {
            "id": 0x7F110001,
            "hex": "0x7f110001",
            "name": "client_secret",
            "value": "super-secret-token",
        }
    }
    symbol_map = {"ApiKeys.client_secret": {0x7F110001}, "client_secret": {0x7F110001}}
    text = "const id = 0x7f110001; ApiKeys.client_secret = use();"

    references, findings = scan_obfuscated_resource_references(
        constants,
        text,
        "src/example.smali",
        resource_map,
        symbol_map,
    )

    assert len(references) == 2
    assert {ref["token"] for ref in references} == {"0x7f110001", "ApiKeys.client_secret"}
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Obfuscated Resource ID Decodes to Sensitive String"
    assert finding.severity == "high"
    assert "client_secret" in finding.evidence


def test_scan_obfuscated_resource_references_returns_empty_when_no_resource_map():
    from utils.mobile.android_resource_helpers import scan_obfuscated_resource_references

    constants = _constants()
    references, findings = scan_obfuscated_resource_references(
        constants,
        "0x7f110001",
        "src/example.smali",
        {},
        {},
    )

    assert references == []
    assert findings == []
