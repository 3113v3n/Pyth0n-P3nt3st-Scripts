import re


def _constants():
    class Constants:
        SECRET_VALUE_RE = re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b"
            r"\s*(?:[:=]|=>)\s*[\"']([^\"'\n]{6,})[\"']"
        )
        NOISE_SECRET_VALUES = {
            "password",
            "secret",
            "changeme",
            "default",
            "dummy",
            "sample",
            "example",
            "test",
        }
        PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{8,}")
        OID_CONTEXT_HINTS = ("oid", "asn1")
        VERSION_CONTEXT_HINTS = ("version", "release")
        NETWORK_CONTEXT_HINTS = ("http://", "host", "endpoint")
        KNOWN_PUBLIC_SERVICE_IPS = {"1.1.1.1", "8.8.8.8"}

        @staticmethod
        def _entropy(value: str) -> float:
            if not value:
                return 0.0
            counts = {}
            for ch in value:
                counts[ch] = counts.get(ch, 0) + 1
            total = len(value)
            import math
            entropy = 0.0
            for count in counts.values():
                p = count / total
                entropy -= p * (0.0 if p == 0 else math.log2(p))
            return entropy

        @staticmethod
        def _snippet_at_index(text: str, index: int, radius: int = 50) -> str:
            start = max(0, index - radius)
            end = min(len(text), index + radius)
            return text[start:end]

    return Constants


def test_is_valuable_secret_evidence_accepts_bearer_token_and_rejects_noise():
    from utils.mobile.secret_helpers import is_valuable_secret_evidence

    constants = _constants()
    assert (
        is_valuable_secret_evidence(
            constants,
            "Bearer/Auth Header Token",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
        )
        is True
    )
    assert (
        is_valuable_secret_evidence(
            constants,
            "Hardcoded Credential Assignment",
            'password = "changeme"',
        )
        is False
    )


def test_is_valuable_secret_evidence_accepts_real_credential_assignment():
    from utils.mobile.secret_helpers import is_valuable_secret_evidence

    constants = _constants()
    assert (
        is_valuable_secret_evidence(
            constants,
            "Hardcoded Credential Assignment",
            'client_secret = "A1b2C3d4E5f6G7h8"',
        )
        is True
    )


def test_extract_printable_strings_filters_and_limits_output():
    from utils.mobile.secret_helpers import extract_printable_strings

    constants = _constants()
    data = b"xxxxfirst-string\x00yyyysecond-string\x00zzzzthird-string"
    result = extract_printable_strings(constants, data, max_strings=2)

    assert result == ["xxxxfirst-string", "yyyysecond-string"]


def test_is_probable_version_ip_flags_version_like_internal_values():
    from utils.mobile.secret_helpers import is_probable_version_ip

    constants = _constants()
    searchable = "release version 1.2.3.4 is embedded here"
    match_start = searchable.index("1.2.3.4")

    assert is_probable_version_ip(constants, "1.2.3.4", searchable, match_start) is True
    assert is_probable_version_ip(constants, "8.8.8.8", searchable, match_start) is False
