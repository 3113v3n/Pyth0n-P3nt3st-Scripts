# iOS Binary Static Analysis Checklist

Use this checklist when you only have an `.ipa` (or extracted `.app`) and need fast, evidence-backed findings from static artifacts.

## Scope

- Input: signed/unsigned iOS app package (`.ipa`) or extracted `Payload/<App>.app`.
- Method: static-only analysis (no jailbreak, no runtime hooks).
- Goal: map each check to concrete artifacts and commands, then map findings into this scanner's report files.

## Quick Extraction

```bash
# 1) Unzip IPA
unzip -q app.ipa -d ipa_out

# 2) Locate app bundle + main Mach-O
APP_DIR="$(find ipa_out/Payload -maxdepth 1 -type d -name '*.app' | head -n1)"
BIN_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_DIR/Info.plist" 2>/dev/null || plutil -extract CFBundleExecutable raw "$APP_DIR/Info.plist")"
BIN_PATH="$APP_DIR/$BIN_NAME"

echo "$APP_DIR"
echo "$BIN_PATH"
```

## Checklist (Artifact -> Command -> What To Flag)

| ID | Check | Artifact | Command(s) | Flag When | Scanner Mapping |
|---|---|---|---|---|---|
| IOS-001 | ATS disabled globally | `Info.plist` | `plutil -p "$APP_DIR/Info.plist" \| rg -n "NSAppTransportSecurity|NSAllowsArbitraryLoads"` | `NSAllowsArbitraryLoads = 1/true` | `*_integrity_findings.txt` (`network_security`) |
| IOS-002 | ATS policy exists | `Info.plist` | `plutil -p "$APP_DIR/Info.plist" \| rg -n "NSAppTransportSecurity"` | ATS dictionary exists and not broad allow | `*_integrity_controls.txt` (`network_security`) |
| IOS-003 | Custom URL schemes / deep links | `Info.plist` | `plutil -p "$APP_DIR/Info.plist" \| rg -n "CFBundleURLTypes|CFBundleURLSchemes"` | non-empty URL scheme declarations | `*_integrity_controls.txt` (`deeplink`) |
| IOS-004 | Sensitive permissions exposure | `Info.plist` | `plutil -p "$APP_DIR/Info.plist" \| rg -n "NS.*UsageDescription"` | excessive/suspicious permission scope | `*_integrity_findings.txt` / `*_integrity_controls.txt` (`privacy`) |
| IOS-005 | Entitlements capability exposure | code-sign entitlements / extracted entitlements | `codesign -d --entitlements :- "$APP_DIR" 2>/dev/null` | broad groups/capabilities (e.g., unusual keychain groups, app groups, iCloud, associated domains) | `*_integrity_findings.txt` / `*_integrity_controls.txt` (`entitlements`, `secure_storage`, `deeplink`, `debugging`) |
| IOS-006 | Linked framework inventory | Mach-O load commands | `otool -L "$BIN_PATH"` | risky/legacy/private frameworks or weak 3rd-party deps | `*_integrity_findings.txt` / `*_integrity_controls.txt` (`dependency`) |
| IOS-007 | Binary hardening posture (PIE) | Mach-O header | `otool -hv "$BIN_PATH"` or `jtool2 -h "$BIN_PATH"` | missing `PIE`/hardening indicators | `*_integrity_findings.txt` / `*_integrity_controls.txt` (`binary_hardening`) |
| IOS-008 | Stack canary signal | symbols/strings | `nm -m "$BIN_PATH" \| rg "__stack_chk_fail|__stack_chk_guard"` and `strings -a "$BIN_PATH" \| rg "__stack_chk_"` | canary symbols absent across binary | `*_integrity_findings.txt` / `*_integrity_controls.txt` (`binary_hardening`) |
| IOS-009 | TLS/pinning bypass indicators | Objective-C selectors/strings | `strings -a "$BIN_PATH" \| rg -ni "sec_trust_evaluate|didReceiveChallenge|allowallhostnameverifier|trustallcerts|hostnameverifier"` | trust-bypass selectors/keywords present | `*_integrity_findings.txt` (`tls`) and `*_integrity_controls.txt` (`pinning`) |
| IOS-010 | Jailbreak / anti-debug indicators | selectors/strings | `strings -a "$BIN_PATH" \| rg -ni "cydia|jailbreak|ptrace|tracerpid|isdebuggerconnected|fork"` | jailbreak/debug keywords present | `*_integrity_controls.txt` (`anti_root`, `anti_debug`) |
| IOS-011 | Hardcoded secrets/tokens | binary + plist + source-like files | `strings -a "$BIN_PATH" \| rg -ni "api[_-]?key|token|secret|password|bearer|eyJ[A-Za-z0-9_-]+"` | credential material or auth headers found | `*_hardcoded.txt`, `*_api_key_checklist.txt` |
| IOS-012 | Backend endpoint inventory | binary + app resources | `strings -a "$BIN_PATH" \| rg -o "https?://[^\"' ]+"` and scanner URL extraction | production/staging/admin URLs present | `*_urls.txt` |
| IOS-013 | Hardcoded IP inventory | binary + app resources | `strings -a "$BIN_PATH" \| rg -n "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b"` | routable/private IP constants present | `*_ips.txt` |
| IOS-014 | Weak crypto indicators | selectors/strings | `strings -a "$BIN_PATH" \| rg -ni "md5|sha1|des|rc4|ecb"` | weak primitives/modes referenced | `*_integrity_findings.txt` (`crypto`) |
| IOS-015 | Raw/encoded secret recovery | base64-like blobs | `strings -a "$BIN_PATH" \| rg -o "[A-Za-z0-9+/_-]{24,}={0,2}"` | decoded payload includes tokens/secrets/endpoints | `*_base64.txt`, `*_base64_raw.txt` |

## Objective-C Metadata Shortcuts

Use these when symbol names are stripped but runtime metadata remains.

```bash
# class-dump (if available)
class-dump -H "$BIN_PATH" -o objc_headers

# jtool2 ObjC metadata (if available)
jtool2 -objc "$BIN_PATH" | rg -ni "URLSession|didReceiveChallenge|SecTrust|Keychain|Jailbreak|ptrace"
```

## Minimal "Triage Pack" Commands

```bash
plutil -p "$APP_DIR/Info.plist"
codesign -d --entitlements :- "$APP_DIR" 2>/dev/null
otool -hv "$BIN_PATH"
otool -L "$BIN_PATH"
strings -a "$BIN_PATH" | rg -ni "https?://|api[_-]?key|token|secret|password|bearer|sec_trust|ptrace|cydia|md5|sha1|des|rc4|ecb"
```

## Mapping To Current Scanner Outputs

- URL/IP/string intelligence:
  - `*_urls.txt`
  - `*_ips.txt`
  - `*_hardcoded.txt`
  - `*_base64.txt`
  - `*_base64_raw.txt`
- API exploitability checks:
  - `*_api_key_checklist.txt`
- Policy/integrity heuristics:
  - `*_integrity_findings.txt`
  - `*_integrity_controls.txt`
- Rollup:
  - `*_summary.json`

## Known Static-Only Limits

- Cannot prove exploitability of authz/session bugs.
- Cannot validate runtime TLS pinning behavior with certainty.
- Cannot confirm code reachability for dead/unused insecure paths.
