import base64
import re


def _constants():
    class Constants:
        BASE64_DATA_URI_PREFIX_RE = re.compile(
            r"(?i)data:(image|font|audio|video|application/(?:pdf|zip|gzip|octet-stream))[^,\n]{0,120};base64,"
        )
        MAX_BASE64_DECODE_BYTES = 8 * 1024 * 1024
        BASE64_MAX_DECODE_DEPTH = 5

        @staticmethod
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
                entropy -= p * (0.0 if p == 0 else __import__("math").log2(p))
            return entropy

    return Constants


def test_beautify_decoded_payload_formats_json_and_xml():
    from utils.mobile.base64_helpers import beautify_decoded_payload

    json_text, json_format = beautify_decoded_payload('{"token":"abc"}')
    xml_text, xml_format = beautify_decoded_payload("<root><token>abc</token></root>")

    assert json_format == "json"
    assert '"token": "abc"' in json_text
    assert xml_format == "xml"
    assert "<root>" in xml_text


def test_is_noise_base64_context_rejects_data_uris():
    from utils.mobile.base64_helpers import is_noise_base64_context

    constants = _constants()
    assert is_noise_base64_context(constants, "data:image/png;base64,AAAA") is True
    assert is_noise_base64_context(constants, "Authorization: Bearer token") is False


def test_decode_base64_if_interesting_returns_sensitive_http_payload():
    from utils.mobile.base64_helpers import decode_base64_if_interesting

    constants = _constants()
    token = base64.b64encode(b"https://api.example.com/v1").decode()

    result = decode_base64_if_interesting(constants, token, context_window="config value")

    assert result == ("https://api.example.com/v1", "text")


def test_decode_base64_if_interesting_rejects_noise_context():
    from utils.mobile.base64_helpers import decode_base64_if_interesting

    constants = _constants()
    token = base64.b64encode(b"https://api.example.com/v1").decode()

    result = decode_base64_if_interesting(
        constants,
        token,
        context_window="data:image/png;base64,",
    )

    assert result is None


def test_build_base64_entry_keeps_expected_fields():
    from utils.mobile.base64_helpers import build_base64_entry

    entry = build_base64_entry("app/config.txt", "YWJj", "abc", "text")

    assert entry == {
        "file": "app/config.txt",
        "format": "text",
        "encoded": "YWJj",
        "decoded": "abc",
    }
