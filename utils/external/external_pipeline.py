"""
external_pipeline.py — Orchestrates the external assessment phases end-to-end.

Each phase is invoked via a small dispatch table, so additional phases can be
added by registering a new (name, callable) pair without touching the pipeline
loop. The pipeline returns a flat dict keyed by phase name; consumers (the
domain class, the report writer, the AI assistant) read the same shape.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from handlers.messages import DisplayHandler

from .domain_recon import DomainRecon
from .external_constants import (
    DEFAULT_PHASES,
    PHASE_PORTS,
    PHASE_PROBE,
    PHASE_RECON,
    PHASE_SCREENSHOTS,
    PHASE_TAKEOVER,
    PHASE_URLS,
    PHASE_VULNS,
)
from .http_probe import HttpProbe
from .port_scanner import PortScanner
from .screenshots import Screenshotter
from .takeover import TakeoverChecker
from .url_collector import UrlCollector
from .vuln_scanner import VulnerabilityScanner


class ExternalPipeline(DisplayHandler):
    """Run the configured external phases for a target domain."""

    def __init__(self, debug: bool = False) -> None:
        super().__init__()
        self._recon = DomainRecon(debug=debug)
        self._http = HttpProbe()
        self._ports = PortScanner()
        self._shots = Screenshotter()
        self._takeover = TakeoverChecker()
        self._urls = UrlCollector()
        self._vulns = VulnerabilityScanner()

    def run(
        self,
        target_domain: str,
        base_dir: Path,
        phases: tuple[str, ...] = DEFAULT_PHASES,
    ) -> tuple[Path, dict]:
        """Execute the requested phases and return (run_dir, results).

        Args:
            target_domain: Root domain (URL prefixes are stripped by recon).
            base_dir:      Parent directory for all run artifacts.
            phases:        Phases to execute, in order.

        Returns:
            Tuple of (run-directory path, phase results dict).
        """
        run_dir = self._build_run_dir(base_dir, target_domain)
        results: dict = {}

        # Dispatch table — each entry receives the run_dir + previous results
        # so later phases can chain off earlier artifacts.
        dispatch = {
            PHASE_RECON: self._run_recon,
            PHASE_PROBE: self._run_probe,
            PHASE_PORTS: self._run_ports,
            PHASE_SCREENSHOTS: self._run_screenshots,
            PHASE_TAKEOVER: self._run_takeover,
            PHASE_URLS: self._run_urls,
            PHASE_VULNS: self._run_vulns,
        }

        for phase in phases:
            handler = dispatch.get(phase)
            if handler is None:
                self.print_warning_message(f"Unknown phase '{phase}' — skipping.")
                continue
            self.print_info_message(f"Running phase: {phase}")
            results[phase] = handler(target_domain, run_dir, results)
            self._print_phase_summary(phase, results[phase])

        return run_dir, results

    # ------------------------------------------------------------------
    # Run-directory layout
    # ------------------------------------------------------------------

    @staticmethod
    def _build_run_dir(base_dir: Path, target_domain: str) -> Path:
        slug = target_domain.replace("https://", "").replace("http://", "").strip("/").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_dir = base_dir / f"{slug}_{timestamp}"
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    # ------------------------------------------------------------------
    # Phase handlers
    # ------------------------------------------------------------------

    def _run_recon(self, domain: str, run_dir: Path, _: dict) -> dict:
        return self._recon.enumerate_subdomain(domain, run_dir)

    def _run_probe(self, _domain: str, run_dir: Path, results: dict) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon)
        if hosts is None:
            return {"json_path": None, "txt_path": None, "count": 0}
        return self._http.probe(hosts, run_dir)

    def _run_ports(self, _domain: str, run_dir: Path, results: dict) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return self._ports.scan(alive, run_dir) if alive else {"normal": None, "grepable": None, "count": 0}

    def _run_screenshots(self, _domain: str, run_dir: Path, results: dict) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return self._shots.capture(alive, run_dir) if alive else {"directory": None, "count": 0}

    def _run_takeover(self, _domain: str, run_dir: Path, results: dict) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon) or recon.get("subdomains_file")
        return self._takeover.check(hosts, run_dir)

    def _run_urls(self, _domain: str, run_dir: Path, results: dict) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon) or recon.get("subdomains_file")
        return self._urls.collect(hosts, run_dir)

    def _run_vulns(self, _domain: str, run_dir: Path, results: dict) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return self._vulns.scan(alive, run_dir) if alive else {"output": None, "total": 0, "severities": {}}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolved_hosts_path(recon_result: dict) -> Path | None:
        """dnsx output keeps lines as 'host [resolved-ip]'; we want only the host."""
        resolved = recon_result.get("resolved_file")
        if not resolved or not Path(resolved).exists():
            return recon_result.get("subdomains_file")

        resolved_path = Path(resolved)
        hosts_only = resolved_path.with_name(resolved_path.stem + "_hosts.txt")
        if hosts_only.exists() and hosts_only.stat().st_size > 0:
            return hosts_only

        seen: set[str] = set()
        for line in resolved_path.read_text(encoding="utf-8", errors="replace").splitlines():
            host = line.split()[0].strip() if line.strip() else ""
            if host:
                seen.add(host)
        if seen:
            hosts_only.write_text("\n".join(sorted(seen)) + "\n", encoding="utf-8")
            return hosts_only
        return recon_result.get("subdomains_file")

    def _print_phase_summary(self, phase: str, result: dict) -> None:
        if result.get("missing"):
            self.print_warning_message(
                f"Phase '{phase}' skipped — missing tool: {result['missing']}"
            )
            return
        # Compact one-line summary so the operator can monitor progress.
        keys_of_interest = ("count", "total", "url_count", "sensitive_count", "resolved_count")
        snippet = ", ".join(
            f"{k}={result[k]}" for k in keys_of_interest if k in result and result.get(k) is not None
        )
        if snippet:
            self.print_success_message(f"Phase '{phase}' done — {snippet}")
        else:
            self.print_success_message(f"Phase '{phase}' done.")
