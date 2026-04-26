from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    severity: str
    file: str
    evidence: str
