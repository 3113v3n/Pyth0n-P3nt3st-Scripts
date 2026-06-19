"""iOS plist and entitlement scanning helpers extracted from mobile static scan helpers."""

from __future__ import annotations

import plistlib
from pathlib import Path

from .models import Finding


def scan_ios_plist(
    root: Path,
    *,
    safe_relpath,
    read_text_if_possible,
) -> tuple[list[Finding], list[Finding]]:
    plist_candidates = [p for p in root.rglob("Info.plist") if p.is_file()]
    if not plist_candidates:
        return [], []

    risks: list[Finding] = []
    controls: list[Finding] = []

    for plist_path in plist_candidates[:3]:
        rel = safe_relpath(plist_path, root)
        try:
            payload = plistlib.loads(plist_path.read_bytes())
        except Exception:
            text = read_text_if_possible(plist_path)
            if "NSAllowsArbitraryLoads" in text:
                risks.append(Finding("network_security", "ATS Arbitrary Loads Detected", "high", rel, "NSAllowsArbitraryLoads"))
            continue

        ats = payload.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            if bool(ats.get("NSAllowsArbitraryLoads")):
                risks.append(Finding("network_security", "ATS Arbitrary Loads Enabled", "high", rel, "NSAllowsArbitraryLoads=true"))
            else:
                controls.append(Finding("network_security", "ATS Policy Present", "info", rel, "NSAppTransportSecurity present"))

            if bool(ats.get("NSAllowsArbitraryLoadsInWebContent")):
                risks.append(Finding("network_security", "ATS Allows Arbitrary Loads in Web Content", "medium", rel, "NSAllowsArbitraryLoadsInWebContent=true"))

            exception_domains = ats.get("NSExceptionDomains", {})
            if isinstance(exception_domains, dict):
                for domain, cfg in exception_domains.items():
                    if not isinstance(cfg, dict):
                        continue
                    if bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads")):
                        risks.append(Finding("network_security", "ATS Exception Domain Allows Insecure HTTP", "high", rel, f"domain={domain} NSExceptionAllowsInsecureHTTPLoads=true"))
                    if bool(cfg.get("NSIncludesSubdomains")):
                        controls.append(Finding("network_security", "ATS Exception Domain Includes Subdomains", "info", rel, f"domain={domain} NSIncludesSubdomains=true"))

        url_types = payload.get("CFBundleURLTypes")
        if url_types:
            controls.append(Finding("deeplink", "Custom URL Schemes Declared", "info", rel, "CFBundleURLTypes present"))

        if bool(payload.get("UIFileSharingEnabled")):
            risks.append(Finding("storage", "iOS File Sharing Enabled", "medium", rel, "UIFileSharingEnabled=true"))

        if bool(payload.get("LSSupportsOpeningDocumentsInPlace")):
            risks.append(Finding("storage", "Documents Open-In-Place Enabled", "low", rel, "LSSupportsOpeningDocumentsInPlace=true"))

        queried_schemes = payload.get("LSApplicationQueriesSchemes")
        if isinstance(queried_schemes, list) and queried_schemes:
            controls.append(Finding("privacy", "Queried URL Schemes Declared", "info", rel, f"LSApplicationQueriesSchemes count={len(queried_schemes)}"))

    entitlement_candidates = [p for p in root.rglob("*.entitlements") if p.is_file()]
    for ent_path in entitlement_candidates[:5]:
        ent_rel = safe_relpath(ent_path, root)
        try:
            ent_payload = plistlib.loads(ent_path.read_bytes())
        except Exception:
            continue

        if bool(ent_payload.get("get-task-allow")):
            risks.append(Finding("debugging", "Debug Entitlement Enabled", "high", ent_rel, "get-task-allow=true"))

        if "com.apple.security.application-groups" in ent_payload:
            controls.append(Finding("storage", "Application Groups Entitlement Present", "info", ent_rel, "com.apple.security.application-groups"))

        if "keychain-access-groups" in ent_payload:
            controls.append(Finding("secure_storage", "Keychain Access Groups Entitlement Present", "info", ent_rel, "keychain-access-groups"))

    return risks, controls
