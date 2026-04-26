"""
external_constants.py — Shared constants for the external assessment module.

Holds default tool flags, port lists, regex filters, and the canonical phase
ordering so individual phase wrappers stay free of magic numbers.
"""

import re

# Canonical phase order. Pipeline runs phases in this order; CLI/UI use the
# names to allow opt-in / skip selections.
PHASE_RECON = "recon"
PHASE_PROBE = "probe"
PHASE_PORTS = "ports"
PHASE_SCREENSHOTS = "screenshots"
PHASE_TAKEOVER = "takeover"
PHASE_URLS = "urls"
PHASE_VULNS = "vulns"

DEFAULT_PHASES = (
    PHASE_RECON,
    PHASE_PROBE,
    PHASE_PORTS,
    PHASE_SCREENSHOTS,
    PHASE_TAKEOVER,
    PHASE_URLS,
    PHASE_VULNS,
)

# httpx default web ports — covers common dev / admin / API ports.
HTTP_PROBE_PORTS = "80,443,8080,8443,3000,5000,7001,8000,8888,9000,9090"

# Default nmap behaviour: top 1000 ports + service version + default scripts.
NMAP_DEFAULT_TOP_PORTS = 1000

# Concurrency caps — kept conservative so the tool runs cleanly in CI/limited boxes.
HTTPX_THREADS = 100
GAUPLUS_THREADS = 30
NUCLEI_CONCURRENCY = 50

# Sensitive file extensions to flag in historical URL output. Used by url_collector.
# Pattern is anchored at the end of the path or before a query string.
SENSITIVE_EXTENSION_RE = re.compile(
    r"\.(zip|tar|tgz|gz|7z|rar|sql|sqlite|db|env|bak|backup|git|svn|hg|"
    r"config|conf|ini|json|xml|yml|yaml|log|md|key|pem|crt|cer|pfx|p12|"
    r"csv|xlsx|xls|docx|doc|pdf|txt|properties)(\?|$)",
    re.IGNORECASE,
)

# Subdomain-takeover detection: subzy is preferred (active maintenance);
# subjack remains as a fallback for environments that already ship it.
TAKEOVER_TOOL_PRIORITY = ("subzy", "subjack")
