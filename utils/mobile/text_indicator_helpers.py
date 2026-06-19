"""Text indicator scanning helpers extracted from mobile static scan helpers."""

from __future__ import annotations

from .models import Finding


def scan_text_for_indicators(constants, text: str, rel_file: str) -> tuple[list[Finding], list[Finding]]:
    lowered = text.lower()
    risks: list[Finding] = []
    controls: list[Finding] = []

    for category, title, severity, needles in constants.RISK_INDICATORS:
        for needle in needles:
            n = needle.lower()
            if n in lowered:
                risks.append(
                    Finding(
                        category=category,
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=constants.clean_line(constants._snippet_around(lowered, n)),
                    )
                )
                break

    for category, title, severity, pattern in constants.ADVANCED_RISK_REGEX:
        match = pattern.search(text)
        if match:
            snippet = constants.clean_line(constants._snippet_around(text, match.group(0)))
            risks.append(
                Finding(
                    category=category,
                    title=title,
                    severity=severity,
                    file=rel_file,
                    evidence=snippet,
                )
            )

    for category, title, severity, needles in constants.CONTROL_INDICATORS:
        for needle in needles:
            n = needle.lower()
            if n in lowered:
                controls.append(
                    Finding(
                        category=category,
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=constants.clean_line(constants._snippet_around(lowered, n)),
                    )
                )
                break

    return risks, controls
