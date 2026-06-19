import re


def _constants():
    class Constants:
        JAVA_STATIC_INT_ASSIGN_RE = re.compile(
            r"\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?int\s+"
            r"([A-Za-z_$][\w$]*)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;"
        )
        SMALI_STATIC_INT_ASSIGN_RE = re.compile(
            r"\.field\s+[^\n]*\s+([A-Za-z_$][\w$]*)\s*:\s*I\s*=\s*(0x[0-9a-fA-F]+|\d+)"
        )
        JAVA_CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)\b")
        SMALI_CLASS_RE = re.compile(r"\.class[^\n]*\s+L([^;]+);")

    return Constants


def test_build_android_obfuscated_maps_uses_public_xml_and_strings(tmp_path):
    from utils.mobile.android_resource_helpers import build_android_obfuscated_maps

    root = tmp_path
    values_dir = root / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '<resources><string name="client_secret">super-secret-value</string></resources>',
        encoding="utf-8",
    )
    (values_dir / "public.xml").write_text(
        '<resources><public type="string" name="client_secret" id="0x7f110001" /></resources>',
        encoding="utf-8",
    )

    resource_map, symbol_map = build_android_obfuscated_maps(
        _constants(),
        root,
        safe_relpath=lambda path, base: str(path.relative_to(base)),
        parse_resource_id=lambda token: int(str(token), 16),
        read_text=lambda path: path.read_text(encoding="utf-8", errors="ignore"),
        register_symbol_id=lambda mapping, symbol, resource_id: mapping.setdefault(symbol, set()).add(resource_id),
    )

    assert resource_map[0x7F110001]["name"] == "client_secret"
    assert resource_map[0x7F110001]["value"] == "super-secret-value"
    assert resource_map[0x7F110001]["source"] == "res/values/strings.xml"
    assert symbol_map == {}


def test_build_android_obfuscated_maps_falls_back_to_r_java_and_builds_symbol_map(tmp_path):
    from utils.mobile.android_resource_helpers import build_android_obfuscated_maps

    root = tmp_path
    values_dir = root / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '<resources><string name="apiToken">token-value-1234</string></resources>',
        encoding="utf-8",
    )
    src_dir = root / "src"
    src_dir.mkdir()
    (src_dir / "R.java").write_text(
        'public final class R { public static final int apiToken = 0x7f110002; }',
        encoding="utf-8",
    )
    (src_dir / "Config.java").write_text(
        'class Config { public static final int apiToken = 0x7f110002; }',
        encoding="utf-8",
    )

    def parse_resource_id(token: str):
        raw = str(token).strip()
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw)

    def register_symbol_id(mapping, symbol, resource_id):
        mapping.setdefault(symbol, set()).add(resource_id)

    resource_map, symbol_map = build_android_obfuscated_maps(
        _constants(),
        root,
        safe_relpath=lambda path, base: str(path.relative_to(base)),
        parse_resource_id=parse_resource_id,
        read_text=lambda path: path.read_text(encoding="utf-8", errors="ignore"),
        register_symbol_id=register_symbol_id,
    )

    assert resource_map[0x7F110002]["name"] == "apiToken"
    assert resource_map[0x7F110002]["source"] == "res/values/strings.xml"
    assert symbol_map["apiToken"] == {0x7F110002}
    assert symbol_map["Config.apiToken"] == {0x7F110002}
