

def _constants():
    class Constants:
        NOISE_SECRET_VALUES = {"password", "secret", "changeme", "default"}

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

    return Constants


def test_parse_android_resource_id_literal_accepts_hex_and_decimal():
    from utils.mobile.android_resource_helpers import parse_android_resource_id_literal

    assert parse_android_resource_id_literal("0x7f110001") == 0x7F110001
    assert parse_android_resource_id_literal("2131820545") == 2131820545
    assert parse_android_resource_id_literal("0") is None
    assert parse_android_resource_id_literal("not-a-number") is None


def test_register_symbol_id_populates_symbol_map_once_per_id():
    from utils.mobile.android_resource_helpers import register_symbol_id

    symbol_map = {}
    register_symbol_id(symbol_map, "ApiKey", 0x7F110001)
    register_symbol_id(symbol_map, "ApiKey", 0x7F110001)
    register_symbol_id(symbol_map, "ApiKey", 0x7F110002)
    register_symbol_id(symbol_map, "", 0x7F110003)

    assert symbol_map == {"ApiKey": {0x7F110001, 0x7F110002}}


def test_is_sensitive_obfuscated_resource_value_detects_real_secret_patterns():
    from utils.mobile.android_resource_helpers import is_sensitive_obfuscated_resource_value

    constants = _constants()
    assert is_sensitive_obfuscated_resource_value(constants, "api_key", "AIzaSyA123456789012345678901234567890") is True
    assert is_sensitive_obfuscated_resource_value(constants, "client_secret", "A1b2C3d4E5f6G7h8") is True
    assert is_sensitive_obfuscated_resource_value(constants, "welcome_text", "hello world") is False
    assert is_sensitive_obfuscated_resource_value(constants, "secret", "changeme") is False


def test_is_sensitive_obfuscated_resource_value_detects_sensitive_urls_with_query_secrets():
    from utils.mobile.android_resource_helpers import is_sensitive_obfuscated_resource_value

    constants = _constants()
    value = "https://api.example.com?api_key=supersecretvalue"
    assert is_sensitive_obfuscated_resource_value(constants, "endpoint", value) is True
