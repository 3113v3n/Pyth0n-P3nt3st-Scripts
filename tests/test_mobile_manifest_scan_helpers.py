

def _constants():
    class Constants:
        DANGEROUS_ANDROID_PERMISSIONS = {"android.permission.READ_SMS"}

    return Constants


def test_scan_android_manifest_returns_empty_without_manifest(tmp_path):
    from utils.mobile.manifest_scan_helpers import scan_android_manifest

    risks, controls = scan_android_manifest(
        _constants(),
        tmp_path,
        safe_relpath=lambda path, root: str(path.relative_to(root)),
        read_text_if_possible=lambda path: path.read_text(encoding="utf-8", errors="ignore") if path.exists() else "",
    )

    assert risks == []
    assert controls == []


def test_scan_android_manifest_detects_exported_components_and_network_config(tmp_path):
    from utils.mobile.manifest_scan_helpers import scan_android_manifest

    root = tmp_path
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
          <uses-permission android:name="android.permission.READ_SMS" />
          <application
              android:debuggable="true"
              android:allowBackup="true"
              android:usesCleartextTraffic="true"
              android:networkSecurityConfig="@xml/network_security_config">
            <activity android:name=".MainActivity">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" />
              </intent-filter>
            </activity>
            <service android:name=".OpenService" android:exported="true" />
          </application>
        </manifest>
        """,
        encoding="utf-8",
    )
    xml_dir = root / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "network_security_config.xml").write_text(
        """
        <network-security-config>
          <base-config cleartextTrafficPermitted="true">
            <trust-anchors>
              <certificates src="user" />
            </trust-anchors>
          </base-config>
          <domain-config>
            <pin-set expiration="2030-01-01">
              <pin digest="SHA-256">abc</pin>
            </pin-set>
          </domain-config>
        </network-security-config>
        """,
        encoding="utf-8",
    )

    risks, controls = scan_android_manifest(
        _constants(),
        root,
        safe_relpath=lambda path, base: str(path.relative_to(base)),
        read_text_if_possible=lambda path: path.read_text(encoding="utf-8", errors="ignore"),
    )

    risk_titles = {finding.title for finding in risks}
    control_titles = {finding.title for finding in controls}

    assert "Manifest Debuggable Enabled" in risk_titles
    assert "Manifest Backup Enabled" in risk_titles
    assert "Manifest Cleartext Traffic Enabled" in risk_titles
    assert "Sensitive Permission Requested" in risk_titles
    assert "Exported Component Without Permission" in risk_titles
    assert "App Links Missing autoVerify" in risk_titles
    assert "Network Security Config Allows Cleartext Traffic" in risk_titles
    assert "Network Security Config Trusts User-Added CAs" in risk_titles
    assert "Network Security Config Declared" in control_titles
    assert "Certificate Pinset Declared in Network Security Config" in control_titles
