def test_scan_ios_plist_returns_empty_without_candidates(tmp_path):
    from utils.mobile.ios_plist_helpers import scan_ios_plist

    risks, controls = scan_ios_plist(
        tmp_path,
        safe_relpath=lambda path, root: str(path.relative_to(root)),
        read_text_if_possible=lambda path: path.read_text(encoding="utf-8", errors="ignore") if path.exists() else "",
    )

    assert risks == []
    assert controls == []


def test_scan_ios_plist_detects_ats_entitlements_and_controls(tmp_path):
    from utils.mobile.ios_plist_helpers import scan_ios_plist

    root = tmp_path
    plist_path = root / "Info.plist"
    plist_path.write_bytes(
        b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>NSAppTransportSecurity</key><dict>
  <key>NSAllowsArbitraryLoads</key><true/>
  <key>NSAllowsArbitraryLoadsInWebContent</key><true/>
  <key>NSExceptionDomains</key><dict>
    <key>example.com</key><dict>
      <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
      <key>NSIncludesSubdomains</key><true/>
    </dict>
  </dict>
</dict>
<key>CFBundleURLTypes</key><array><dict/></array>
<key>UIFileSharingEnabled</key><true/>
<key>LSSupportsOpeningDocumentsInPlace</key><true/>
<key>LSApplicationQueriesSchemes</key><array><string>fb</string></array>
</dict></plist>'''
    )
    ent_path = root / "Debug.entitlements"
    ent_path.write_bytes(
        b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>get-task-allow</key><true/>
<key>com.apple.security.application-groups</key><array><string>group.app</string></array>
<key>keychain-access-groups</key><array><string>keychain.group</string></array>
</dict></plist>'''
    )

    risks, controls = scan_ios_plist(
        root,
        safe_relpath=lambda path, base: str(path.relative_to(base)),
        read_text_if_possible=lambda path: path.read_text(encoding="utf-8", errors="ignore"),
    )

    risk_titles = {finding.title for finding in risks}
    control_titles = {finding.title for finding in controls}

    assert "ATS Arbitrary Loads Enabled" in risk_titles
    assert "ATS Allows Arbitrary Loads in Web Content" in risk_titles
    assert "ATS Exception Domain Allows Insecure HTTP" in risk_titles
    assert "iOS File Sharing Enabled" in risk_titles
    assert "Documents Open-In-Place Enabled" in risk_titles
    assert "Debug Entitlement Enabled" in risk_titles
    assert "ATS Exception Domain Includes Subdomains" in control_titles
    assert "Custom URL Schemes Declared" in control_titles
    assert "Queried URL Schemes Declared" in control_titles
    assert "Application Groups Entitlement Present" in control_titles
    assert "Keychain Access Groups Entitlement Present" in control_titles
