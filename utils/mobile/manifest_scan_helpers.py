"""Android manifest scanning helpers extracted from mobile static scan helpers."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding


def scan_android_manifest(
    constants,
    root: Path,
    *,
    safe_relpath,
    read_text_if_possible,
) -> tuple[list[Finding], list[Finding]]:
    manifest = root / "AndroidManifest.xml"
    if not manifest.exists():
        return [], []

    text = read_text_if_possible(manifest)
    if not text:
        return [], []

    rel = safe_relpath(manifest, root)
    risks: list[Finding] = []
    controls: list[Finding] = []

    if 'android:debuggable="true"' in text:
        risks.append(Finding("debugging", "Manifest Debuggable Enabled", "high", rel, 'android:debuggable="true"'))
    if 'android:allowBackup="true"' in text:
        risks.append(Finding("backup", "Manifest Backup Enabled", "medium", rel, 'android:allowBackup="true"'))
    if 'android:usesCleartextTraffic="true"' in text:
        risks.append(Finding("network_security", "Manifest Cleartext Traffic Enabled", "high", rel, 'android:usesCleartextTraffic="true"'))
    if 'android:requestLegacyExternalStorage="true"' in text:
        risks.append(Finding("storage", "Legacy External Storage Access Requested", "medium", rel, 'android:requestLegacyExternalStorage="true"'))

    if "android:networkSecurityConfig=" in text:
        controls.append(Finding("pinning", "Network Security Config Declared", "info", rel, "android:networkSecurityConfig"))

    try:
        manifest_xml = ET.fromstring(text)
    except ET.ParseError:
        return risks, controls

    android_ns = "{http://schemas.android.com/apk/res/android}"

    def attr(element: ET.Element, key: str) -> str:
        return str(element.get(f"{android_ns}{key}") or element.get(f"android:{key}") or "").strip()

    uses_sdk = manifest_xml.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = attr(uses_sdk, "minSdkVersion")
        target_sdk = attr(uses_sdk, "targetSdkVersion")
        if min_sdk.isdigit() and int(min_sdk) < 24:
            risks.append(Finding("platform_hardening", "Manifest Minimum SDK Supports Legacy Android Versions", "medium", rel, f"minSdkVersion={min_sdk}"))
        if target_sdk.isdigit() and int(target_sdk) < 31:
            risks.append(Finding("platform_hardening", "Manifest Target SDK Is Outdated", "medium", rel, f"targetSdkVersion={target_sdk}"))

    for permission in manifest_xml.findall("uses-permission"):
        name = attr(permission, "name")
        if name in constants.DANGEROUS_ANDROID_PERMISSIONS:
            risks.append(Finding("permission_model", "Sensitive Permission Requested", "low", rel, name))

    application_node = manifest_xml.find("application")
    if application_node is None:
        return risks, controls

    full_backup = attr(application_node, "fullBackupContent")
    data_extraction_rules = attr(application_node, "dataExtractionRules")
    if full_backup or data_extraction_rules:
        controls.append(
            Finding(
                "backup",
                "Backup/Data Extraction Rules Declared",
                "info",
                rel,
                ", ".join(
                    value
                    for value in [
                        f"fullBackupContent={full_backup}" if full_backup else "",
                        f"dataExtractionRules={data_extraction_rules}" if data_extraction_rules else "",
                    ]
                    if value
                ),
            )
        )

    network_config_ref = attr(application_node, "networkSecurityConfig")
    if network_config_ref.startswith("@xml/"):
        config_name = network_config_ref.split("/", 1)[1]
        config_path = root / "res" / "xml" / f"{config_name}.xml"
        if config_path.exists():
            config_text = read_text_if_possible(config_path)
            config_rel = safe_relpath(config_path, root)
            if 'cleartextTrafficPermitted="true"' in config_text:
                risks.append(Finding("network_security", "Network Security Config Allows Cleartext Traffic", "high", config_rel, 'cleartextTrafficPermitted="true"'))
            if 'src="user"' in config_text:
                risks.append(Finding("network_security", "Network Security Config Trusts User-Added CAs", "medium", config_rel, 'certificates src="user"'))
            if "<pin-set" in config_text:
                controls.append(Finding("pinning", "Certificate Pinset Declared in Network Security Config", "info", config_rel, "pin-set"))

    component_tags = ("activity", "service", "receiver", "provider")
    for tag in component_tags:
        for component in application_node.findall(tag):
            exported = attr(component, "exported").lower()
            permission = attr(component, "permission") or attr(component, "readPermission") or attr(component, "writePermission")
            has_intent_filter = bool(component.findall("intent-filter"))
            is_exposed = exported == "true" or (not exported and has_intent_filter)
            if is_exposed:
                comp_name = attr(component, "name") or "<unnamed>"
                evidence = f"{tag}={comp_name} exported={exported or 'implicit'}"
                if permission:
                    evidence = f"{evidence} permission={permission}"
                sev = "high" if not permission else "medium"
                title = "Exported Component Without Permission" if not permission else "Exported Component"
                risks.append(Finding("component_exposure", title, sev, rel, evidence))

            if tag == "activity":
                task_affinity = attr(component, "taskAffinity")
                allow_task_reparenting = attr(component, "allowTaskReparenting").lower() == "true"
                if task_affinity and allow_task_reparenting:
                    risks.append(Finding("task_hijacking", "Activity Task Affinity + Reparenting Enabled", "medium", rel, f"activity={attr(component, 'name') or '<unnamed>'} taskAffinity={task_affinity}"))

            for intent_filter in component.findall("intent-filter"):
                action_names = {attr(action, "name") for action in intent_filter.findall("action") if attr(action, "name")}
                category_names = {attr(category, "name") for category in intent_filter.findall("category") if attr(category, "name")}
                schemes = {attr(data_node, "scheme").lower() for data_node in intent_filter.findall("data") if attr(data_node, "scheme")}
                has_http_scheme = bool({"http", "https"} & schemes)
                is_view_browsable = "android.intent.action.VIEW" in action_names and "android.intent.category.BROWSABLE" in category_names
                if is_view_browsable and has_http_scheme:
                    auto_verify = attr(intent_filter, "autoVerify").lower()
                    if auto_verify != "true":
                        risks.append(Finding("deeplink", "App Links Missing autoVerify", "medium", rel, f"activity={attr(component, 'name') or '<unnamed>'} schemes={','.join(sorted(schemes))}"))

    return risks, controls
