"""Artifact path and taxonomy persistence helpers for mobile command orchestration."""

from __future__ import annotations

import json
from pathlib import Path


def build_artifact_paths(basename: Path) -> dict[str, Path]:
    base = str(basename)
    return {
        "urls": Path(f"{base}_urls.txt"),
        "ips": Path(f"{base}_ips.txt"),
        "hardcoded": Path(f"{base}_hardcoded.txt"),
        "api_key_checklist": Path(f"{base}_api_key_checklist.txt"),
        "base64": Path(f"{base}_base64.txt"),
        "obfuscated_string_map": Path(f"{base}_obfuscated_string_map.txt"),
        "integrity_findings": Path(f"{base}_integrity_findings.txt"),
        "integrity_controls": Path(f"{base}_integrity_controls.txt"),
        "summary": Path(f"{base}_summary.json"),
        "taxonomy": Path(f"{base}_masvs_mastg.json"),
    }



def write_taxonomy_report(taxonomy_file: Path, taxonomy_report: dict) -> int:
    entries = taxonomy_report.get("entries") or []
    if not entries:
        return 0
    taxonomy_file.write_text(
        json.dumps(taxonomy_report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return len(entries)
