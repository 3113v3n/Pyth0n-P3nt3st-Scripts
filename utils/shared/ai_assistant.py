"""
ai_assistant.py — Claude AI integration for the pentest framework.

PentestAI wraps the Anthropic Python SDK and exposes domain-specific analysis
methods that each framework module can call to enrich its output:

  • VA module     — executive summary of vulnerability findings + false-positive flags
  • Mobile module — classify hardcoded strings as genuinely sensitive or benign
  • Password module — identify password policy weaknesses from cracked patterns
  • Internal module — suggest likely host roles from discovered IP ranges

Usage
-----
The assistant is enabled by default when the ANTHROPIC_API_KEY environment
variable is set. Pass --no-ai to main.py to disable it.

    from utils.shared.ai_assistant import PentestAI

    ai = PentestAI()
    summary = ai.summarize_vulnerabilities(vuln_dataframe)

All methods degrade gracefully: if the API key is absent or a call fails, they
return a plain-text placeholder so the rest of the workflow is not interrupted.
"""

from __future__ import annotations

import importlib
import os
import textwrap
from typing import Optional

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False


# Default model — the most capable Claude model as of the knowledge cutoff.
DEFAULT_MODEL = "claude-opus-4-6"
# Hard cap on tokens sent to the API to avoid runaway costs on large datasets.
MAX_CONTEXT_CHARS = 8_000


class PentestAI:
    """Claude-powered analysis assistant for pentest framework modules.

    Attributes:
        model:    Anthropic model ID to use for all requests.
        enabled:  False if the API key is missing — methods return placeholders.
    """

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        self._client = None

        try:
            anthropic_module = importlib.import_module("anthropic")
        except ImportError:
            print(
                "[AI] anthropic package not installed. "
                "Run `pip install anthropic` to enable AI features."
            )
            self.enabled = False
            return

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print(
                "[AI] ANTHROPIC_API_KEY environment variable not set. "
                "AI features are disabled. Export the key to enable them."
            )
            self.enabled = False
            return

        self._client = anthropic_module.Anthropic(api_key=api_key)
        self.enabled = True

    # ------------------------------------------------------------------
    # Core API call
    # ------------------------------------------------------------------

    def _ask(self, system_prompt: str, user_content: str) -> str:
        """Send a single-turn message to Claude and return the response text.

        Args:
            system_prompt: Instructions that define Claude's role and constraints.
            user_content:  The actual question or data to analyze.

        Returns:
            Claude's response as a plain string, or an error placeholder.
        """
        if not self.enabled or self._client is None:
            return "[AI features disabled — set ANTHROPIC_API_KEY to enable]"

        # Truncate very long inputs to stay within practical limits.
        if len(user_content) > MAX_CONTEXT_CHARS:
            user_content = user_content[:MAX_CONTEXT_CHARS] + "\n...[truncated]"

        try:
            message = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )
            return message.content[0].text
        except Exception as error:
            return f"[AI analysis unavailable: {error}]"

    # ------------------------------------------------------------------
    # VA module integration
    # ------------------------------------------------------------------

    def summarize_vulnerabilities(self, vuln_df: "pd.DataFrame") -> str:
        """Generate an executive summary of a vulnerability assessment dataframe.

        [AI-HOOK] Called from vulnerability_module.py after sort_vulnerabilities()
        writes the main Excel report; the summary is appended as an "AI Summary" sheet.

        Args:
            vuln_df: DataFrame containing categorised vulnerability findings.

        Returns:
            Plain-text executive summary with severity counts, top findings, and
            prioritised remediation recommendations.
        """
        if not _PANDAS_AVAILABLE or vuln_df is None or vuln_df.empty:
            return "[No vulnerability data available for AI analysis]"

        # Build a compact stats block without sending raw PII (hostnames/IPs).
        try:
            stats_lines = []
            if "Risk" in vuln_df.columns:
                counts = vuln_df["Risk"].value_counts().to_dict()
                stats_lines.append(f"Severity counts: {counts}")
            if "Name" in vuln_df.columns:
                top_findings = vuln_df["Name"].value_counts().head(10).to_dict()
                stats_lines.append(f"Top 10 finding types: {top_findings}")
            if "category" in vuln_df.columns:
                by_category = vuln_df["category"].value_counts().to_dict()
                stats_lines.append(f"Findings by category: {by_category}")

            stats_block = "\n".join(stats_lines) if stats_lines else str(vuln_df.head(20))
        except Exception:
            stats_block = str(vuln_df.head(20))

        system_prompt = textwrap.dedent("""
            You are a senior penetration testing consultant writing an executive summary
            for a client vulnerability assessment report. Be concise (under 300 words),
            professional, and focus on business impact. Do not repeat raw numbers
            verbatim — synthesize them into insights. Use plain text without markdown.
        """)

        user_content = (
            "Summarize the following vulnerability assessment statistics for "
            "an executive audience. Include: overall risk posture, the top 3 "
            "most critical issue types, and prioritised remediation steps.\n\n"
            f"{stats_block}"
        )

        return self._ask(system_prompt, user_content)

    def flag_false_positives(self, finding_name: str, plugin_output: str) -> str:
        """Assess whether a vulnerability finding is likely a false positive.

        [AI-HOOK] Called from filter_vulnerabilities.py after categorisation.

        Args:
            finding_name:  The vulnerability title / plugin name.
            plugin_output: Raw plugin output text from the scanner.

        Returns:
            "LIKELY_FP", "UNLIKELY_FP", or "UNCERTAIN" with a one-sentence reason.
        """
        system_prompt = textwrap.dedent("""
            You are a vulnerability assessment expert. Classify findings as false
            positives based on scanner plugin output. Respond with EXACTLY one of:
            LIKELY_FP, UNLIKELY_FP, UNCERTAIN — followed by a colon and a single
            sentence explanation. Example: "LIKELY_FP: Scanner detected SSL version
            string but service is actually TLS 1.3."
        """)

        user_content = (
            f"Finding: {finding_name}\n\n"
            f"Plugin output (excerpt):\n{plugin_output[:2000]}"
        )

        return self._ask(system_prompt, user_content)

    # ------------------------------------------------------------------
    # Mobile module integration
    # ------------------------------------------------------------------

    def analyze_mobile_findings(self, findings: dict) -> str:
        """Classify mobile static analysis findings by sensitivity.

        [AI-HOOK] Called from mobile_commands.py after inspect_application_files()
        completes. Results are printed to console and saved alongside other outputs.

        Args:
            findings: Dictionary with keys "hardcoded", "urls", "ips", "base64"
                      each containing a list of extracted strings.

        Returns:
            A structured report identifying which findings are genuinely sensitive
            (API keys, tokens, private IPs) versus likely benign (library URLs,
            public CDN addresses, build-system paths).
        """
        system_prompt = textwrap.dedent("""
            You are a mobile application security expert performing static analysis
            triage. Classify findings as SENSITIVE or BENIGN with brief reasoning.
            Focus on: hardcoded credentials, private API keys, internal IP addresses,
            authentication tokens, and cryptographic secrets. Format output as a
            concise bullet list. Use plain text without markdown.
        """)

        summary_lines = []
        for category, items in findings.items():
            if items:
                sample = items[:10]
                summary_lines.append(f"{category.upper()} ({len(items)} total, sample):\n" +
                                     "\n".join(f"  - {item}" for item in sample))

        if not summary_lines:
            return "[No mobile findings to analyze]"

        user_content = (
            "Analyze these mobile application static analysis findings and "
            "identify which are genuinely sensitive security issues:\n\n"
            + "\n\n".join(summary_lines)
        )

        return self._ask(system_prompt, user_content)

    # ------------------------------------------------------------------
    # Password module integration
    # ------------------------------------------------------------------

    def analyze_password_patterns(self, password_list: list[str]) -> str:
        """Identify password policy weaknesses from a list of cracked passwords.

        [AI-HOOK] Called from password_module.py after generate_password_list_from_hashes()
        writes the output file.

        Args:
            password_list: List of plaintext passwords recovered from hash cracking.

        Returns:
            Analysis of common patterns, complexity failures, and recommended
            password policy improvements.
        """
        if not password_list:
            return "[No passwords to analyze]"

        # Send a sample — avoid sending all credentials over the API.
        sample = password_list[:50]
        patterns_preview = "\n".join(sample)

        system_prompt = textwrap.dedent("""
            You are a security consultant analyzing password policy compliance.
            Do NOT reproduce individual passwords. Describe patterns observed
            (e.g. "company name + year", "season + number") and recommend
            specific Active Directory password policy improvements. Plain text,
            under 200 words.
        """)

        user_content = (
            f"Analyze the following {len(password_list)} cracked passwords "
            "(sample shown) and identify policy weaknesses:\n\n"
            f"{patterns_preview}"
        )

        return self._ask(system_prompt, user_content)

    # ------------------------------------------------------------------
    # External PT module integration
    # ------------------------------------------------------------------

    def analyze_external_findings(self, target_domain: str, phase_results: dict) -> str:
        """Summarise external assessment phase results into a narrative report.

        [AI-HOOK] Called from external_module.py after the pipeline completes.

        Args:
            target_domain: The root domain that was assessed.
            phase_results: Mapping of phase name → result dict produced by
                           ExternalPipeline.run().

        Returns:
            Plain-text narrative covering attack surface, key risks, and
            recommended next steps.
        """
        if not phase_results:
            return "[No external phase results to analyze]"

        # Build a compact stats block — avoid sending raw URLs / hostnames in bulk.
        stats_lines: list[str] = [f"Target domain: {target_domain}"]
        for phase, result in phase_results.items():
            if not result:
                continue
            if result.get("missing"):
                stats_lines.append(f"{phase}: skipped (missing {result['missing']})")
                continue

            counts = {
                key: value
                for key, value in result.items()
                if isinstance(value, (int, dict)) and value
            }
            if counts:
                stats_lines.append(f"{phase}: {counts}")

        system_prompt = textwrap.dedent("""
            You are a senior external penetration testing consultant. Read the
            phase summary statistics and produce: (1) a one-paragraph attack
            surface overview, (2) the top three risks worth investigating
            manually, and (3) the recommended next steps. Be concrete but
            concise (under 250 words). Plain text — no markdown.
        """)

        user_content = (
            "Summarise the following external assessment statistics for "
            "an engagement debrief:\n\n" + "\n".join(stats_lines)
        )
        return self._ask(system_prompt, user_content)

    # ------------------------------------------------------------------
    # Internal PT module integration
    # ------------------------------------------------------------------

    def suggest_host_roles(self, ip_list: list[str]) -> str:
        """Infer likely host roles from IP addresses discovered during network enumeration.

        [AI-HOOK] Called from internal_module.py after enumerate_hosts() completes.

        Args:
            ip_list: List of live IP address strings discovered on the network.

        Returns:
            A formatted network map suggesting likely roles (DC, file server,
            database, workstation) based on IP range patterns and common conventions.
        """
        if not ip_list:
            return "[No hosts discovered]"

        ip_sample = ip_list[:100]
        ip_block = "\n".join(ip_sample)

        system_prompt = textwrap.dedent("""
            You are a network security analyst. Based on IP address patterns and
            subnet conventions, suggest likely roles for discovered hosts. Be
            specific but acknowledge uncertainty. Format as a compact table:
            IP Range | Likely Role | Confidence. Plain text, no markdown.
        """)

        user_content = (
            f"The following {len(ip_list)} live hosts were discovered during "
            "an internal network scan. Suggest their likely roles based on "
            "IP ranges and common enterprise network conventions:\n\n"
            f"{ip_block}"
        )

        return self._ask(system_prompt, user_content)
