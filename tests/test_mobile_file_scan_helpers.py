import base64
import re


def _constants():
    class Constants:
        BINARY_SKIP_EXTENSIONS = {".png"}
        MAX_FILE_SIZE_BYTES = 1024
        TEXT_EXTENSIONS = {".txt"}
        MAX_STRINGS_PER_FILE = 10
        MAX_TEXT_CHARS_PER_FILE = 10000
        URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
        IP_RE = re.compile(r"(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.\d)")
        SECRET_PATTERNS = [
            ("Hardcoded Credential Assignment", "high", re.compile(r'password\s*=\s*"[^"]+"', re.IGNORECASE))
        ]
        BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")

    return Constants


def test_scan_single_file_skips_oversized_binary(tmp_path):
    from utils.mobile.file_scan_helpers import scan_single_file

    constants = _constants()
    file_path = tmp_path / "image.png"
    file_path.write_bytes(b"x" * 2048)

    result = scan_single_file(
        constants,
        file_path,
        tmp_path,
        safe_relpath=lambda path, root: str(path.relative_to(root)),
        extract_printable_strings=lambda data, max_strings: [],
        is_valuable_url=lambda url: True,
        canonicalize_url=lambda url: url,
        is_probable_version_ip=lambda ip, text, start: False,
        normalize_line_no_truncate=lambda text: " ".join(str(text).split()),
        is_valuable_secret_evidence=lambda title, evidence: True,
        scan_obfuscated_resource_references=lambda text, rel_file: ([], []),
        decode_base64_if_interesting=lambda token, context_window="": None,
        build_base64_entry=lambda rel_file, token, decoded_text, decoded_format: {},
        scan_text_for_indicators=lambda text, rel_file: ([], []),
    )

    assert result["skipped"] is True
    assert result["bytes_scanned"] == 0


def test_scan_single_file_collects_urls_secrets_base64_and_risks(tmp_path):
    from utils.mobile.file_scan_helpers import scan_single_file

    constants = _constants()
    token = base64.b64encode(b"https://api.example.com/secret").decode()
    file_path = tmp_path / "config.txt"
    file_path.write_text(
        f'https://example.com\nhttp://insecure.local\npassword = "supersecret123"\n{token}\n',
        encoding="utf-8",
    )

    result = scan_single_file(
        constants,
        file_path,
        tmp_path,
        safe_relpath=lambda path, root: str(path.relative_to(root)),
        extract_printable_strings=lambda data, max_strings: [],
        is_valuable_url=lambda url: True,
        canonicalize_url=lambda url: url.rstrip("/"),
        is_probable_version_ip=lambda ip, text, start: False,
        normalize_line_no_truncate=lambda text: " ".join(str(text).split()),
        is_valuable_secret_evidence=lambda title, evidence: True,
        scan_obfuscated_resource_references=lambda text, rel_file: ([{"token": "0x7f110001"}], []),
        decode_base64_if_interesting=lambda token, context_window="": ("https://api.example.com/secret", "text"),
        build_base64_entry=lambda rel_file, token, decoded_text, decoded_format: {
            "file": rel_file,
            "encoded": token,
            "decoded": decoded_text,
            "format": decoded_format,
        },
        scan_text_for_indicators=lambda text, rel_file: (["risk"], ["control"]),
    )

    assert result["file"] == "config.txt"
    assert result["skipped"] is False
    assert "https://example.com" in result["urls"]
    assert "http://insecure.local" in result["urls"]
    assert len(result["hardcoded"]) == 1
    assert result["obfuscated_refs"] == [{"token": "0x7f110001"}]
    assert len(result["base64"]) == 1
    assert any(getattr(finding, "title", "") == "Potential Cleartext Backend Endpoint" for finding in result["risk_findings"])
    assert "risk" in result["risk_findings"]
    assert "control" in result["control_findings"]
