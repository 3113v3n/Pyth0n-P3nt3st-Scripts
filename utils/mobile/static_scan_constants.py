"""Constants and regex collections used by mobile static scanning."""

from __future__ import annotations

import re


class MobileStaticScanConstants:
    """Shared static-scan constants for Android/iOS artifact analysis."""

    MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024
    MAX_TEXT_CHARS_PER_FILE = 500_000
    MAX_STRINGS_PER_FILE = 5_000
    THREAD_FACTOR = 2
    NUCLEI_TEMPLATE_SYNC_TTL_SECONDS = 24 * 60 * 60

    PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{8,}")
    URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
    IP_RE = re.compile(
        r"(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.\d)"
    )
    URL_TRAILING_JUNK_RE = re.compile(r"[.,;:)\]}>\"']+$")
    URL_PLACEHOLDER_RE = re.compile(r"%[a-zA-Z]")
    HOSTNAME_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
        re.IGNORECASE,
    )
    IPV4_EXACT_RE = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
    )
    IP_CONTEXT_RE = re.compile(
        r"(?i)\b(?:ip|host|addr|address|src|source|dst|dest|destination|from|to|endpoint|server|dns)\b"
    )
    BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")
    BASE64_MAX_DECODE_DEPTH = 5
    MAX_BASE64_DECODE_BYTES = 8 * 1024 * 1024

    TEXT_EXTENSIONS = {
        ".xml", ".json", ".txt", ".cfg", ".conf", ".ini", ".properties", ".yaml", ".yml",
        ".js", ".html", ".htm", ".css", ".csv", ".md", ".smali", ".java", ".kt", ".kts",
        ".swift", ".m", ".mm", ".plist", ".entitlements", ".gradle", ".pro", ".pbxproj",
    }
    BINARY_SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".mp3", ".wav", ".ogg",
        ".mp4", ".mov", ".avi", ".ttf", ".otf", ".woff", ".woff2", ".so",
    }

    URL_IGNORE_RE = re.compile(
        r"\.(?:css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)(?:\?|$)",
        re.IGNORECASE,
    )
    URL_NOISE_HOSTS = {
        "schemas.android.com",
        "android.googlesource.com",
        "www.w3.org",
    }
    REPO_REFERENCE_HOSTS = {"github.com", "www.github.com", "gitlab.com", "bitbucket.org"}
    NETWORK_CONTEXT_HINTS = (
        "http://", "https://", "wss://", "host", "ip", "endpoint",
        "server", "socket", "connect", "address", "dns",
    )
    VERSION_CONTEXT_HINTS = (
        "version", "openssl", "libssl", "changelog", "release", "build", "sdk",
    )
    OID_CONTEXT_HINTS = (
        "oid", "asn1", "x509", "pkcs", "objectidentifier", "object identifier",
    )
    KNOWN_PUBLIC_SERVICE_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}
    DANGEROUS_ANDROID_PERMISSIONS = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
    }

    SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
        ("AWS Access Key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("Google API Key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("Stripe Live Key", "high", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
        ("GitHub Token", "high", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        (
            "JWT Token",
            "medium",
            re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        ),
        (
            "Hardcoded Credential Assignment",
            "high",
            re.compile(
                r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b"
                r"\s*(?:[:=]|=>)\s*[\"'][^\"'\n]{6,}[\"']"
            ),
        ),
        (
            "Bearer/Auth Header Token",
            "high",
            re.compile(r"(?i)\b(?:authorization|bearer)\b[^\n]{0,120}"),
        ),
    ]

    NOISE_SECRET_VALUES = {
        "password", "passwd", "secret", "token", "apikey", "api_key", "changeme",
        "default", "dummy", "sample", "example", "test", "none", "null", "undefined",
        "your_password", "your_token", "insert_here",
    }
    SECRET_VALUE_RE = re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b"
        r"\s*(?:[:=]|=>)\s*[\"']([^\"'\n]{6,})[\"']"
    )

    RISK_INDICATORS: list[tuple[str, str, str, tuple[str, ...]]] = [
        (
            "webview",
            "Potentially Unsafe WebView Usage",
            "medium",
            (
                "setjavascriptenabled(true)",
                "addjavascriptinterface(",
                "setallowfileaccess(true)",
                "setallowuniversalaccessfromfileurls(true)",
                "onreceivedsslerror",
                ".proceed()",
            ),
        ),
        (
            "tls",
            "Potential TLS Trust Bypass",
            "high",
            (
                "allowallhostnameverifier",
                "trustallcerts",
                "x509trustmanager",
                "hostnameverifier",
            ),
        ),
        (
            "deeplink",
            "Potential Deep Link Attack Surface",
            "low",
            (
                "android.intent.action.view",
                "cfbundleurltypes",
                "openurl(",
                "continueuseractivity",
            ),
        ),
    ]

    ADVANCED_RISK_REGEX: list[tuple[str, str, str, re.Pattern[str]]] = [
        (
            "hardcoded_secret",
            "Embedded Private Key Material",
            "critical",
            re.compile(
                r"-----BEGIN(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----",
                re.IGNORECASE,
            ),
        ),
        (
            "crypto",
            "Weak Hash Algorithm Usage",
            "high",
            re.compile(r"(?i)messagedigest\.getinstance\(\"(?:md5|sha-1)\"\)"),
        ),
        (
            "crypto",
            "Weak Cipher Mode (ECB) Usage",
            "high",
            re.compile(r"(?i)cipher\.getinstance\(\"[^\"]*ecb[^\"]*\"\)"),
        ),
        (
            "crypto",
            "Weak Cipher Algorithm Usage",
            "high",
            re.compile(r"(?i)cipher\.getinstance\(\"(?:des|desede|rc2|rc4)[^\"]*\"\)"),
        ),
        (
            "webview",
            "WebView Mixed Content Always Allow",
            "high",
            re.compile(r"(?i)setmixedcontentmode\s*\(\s*websettings\.mixed_content_always_allow"),
        ),
        (
            "webview",
            "WebView File URL Access Relaxed",
            "high",
            re.compile(r"(?i)setallowfileaccessfromfileurls\s*\(\s*true\s*\)"),
        ),
        (
            "crypto",
            "Potential Insecure PRNG (SHA1PRNG)",
            "medium",
            re.compile(r"(?i)sha1prng"),
        ),
        (
            "logging",
            "Sensitive Data Logged to Console",
            "medium",
            re.compile(r"(?i)log\.[vdiew]\([^\n]*(?:password|token|secret|api[_-]?key)"),
        ),
        (
            "data_access",
            "Potential SQL Injection Sink (rawQuery Concatenation)",
            "high",
            re.compile(r"(?i)rawquery\s*\([^\n]*\+[^\n]*\)"),
        ),
        (
            "data_access",
            "Potential SQL Injection Sink (execSQL Concatenation)",
            "high",
            re.compile(r"(?i)execsql\s*\([^\n]*\+[^\n]*\)"),
        ),
        (
            "storage",
            "Legacy World-Readable/Writeable Storage Mode",
            "high",
            re.compile(r"(?i)\bMODE_WORLD_(?:READABLE|WRITEABLE)\b"),
        ),
        (
            "logging",
            "Sensitive Data Logged in NSLog/print",
            "medium",
            re.compile(r"(?i)\b(?:nslog|print)\s*\([^\n]*(?:password|token|secret|api[_-]?key)"),
        ),
        (
            "intent_security",
            "Potential Broadcast Exposure (Heuristic)",
            "low",
            re.compile(r"(?i)\bsendbroadcast\s*\("),
        ),
    ]

    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1,
    }

    CONTROL_INDICATORS: list[tuple[str, str, str, tuple[str, ...]]] = [
        (
            "integrity",
            "Play Integrity/SafetyNet Signal",
            "info",
            ("integritymanager", "play integrity", "safetynet", "ctsprofilematch", "basicintegrity"),
        ),
        (
            "anti_tamper",
            "App Signature Validation Logic",
            "info",
            (
                "getsigningcertificates",
                "packageinfo.signatures",
                "signinginfo",
                "getpackageinfo(",
                "certificatefactory.getinstance",
                "messagedigest.getinstance(\"sha-256\")",
            ),
        ),
        (
            "anti_root",
            "Root/Jailbreak Detection Logic",
            "info",
            (
                "isdevice rooted",
                "jailbreak",
                "cydia",
                "magisk",
                "su/bin/su",
                "test-keys",
                "ro.debuggable",
                "ro.secure",
            ),
        ),
        (
            "anti_debug",
            "Anti-Debugging Signal",
            "info",
            ("isdebuggerconnected", "debugger", "ptrace", "tracerpid"),
        ),
        (
            "pinning",
            "Certificate Pinning Signal",
            "info",
            ("certificatepinner", "network_security_config", "sec_trust_evaluate", "trustkit"),
        ),
        (
            "secure_storage",
            "Secure Storage API Usage",
            "info",
            ("androidkeystore", "encryptedsharedpreferences", "keychain", "ksecattr"),
        ),
    ]
