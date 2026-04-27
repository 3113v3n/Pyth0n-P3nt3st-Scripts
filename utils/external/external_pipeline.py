"""
external_pipeline.py — Orchestrates the external assessment phases end-to-end.

Each phase is invoked via a small dispatch table, so additional phases can be
added by registering a new (name, callable) pair without touching the pipeline
loop. The pipeline returns a flat dict keyed by phase name; consumers (the
domain class, the report writer, the AI assistant) read the same shape.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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
    SAFE_MAX_TARGETS_PER_PHASE,
    SAFE_MODE_ALLOWED_PHASES,
    SAFE_OPERATOR_TAG_DEFAULT,
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
        safe_mode: bool = False,
        operator_tag: str = SAFE_OPERATOR_TAG_DEFAULT,
    ) -> tuple[Path, dict]:
        """Execute the requested phases and return (run_dir, results).

        Args:
            target_domain: Root domain (URL prefixes are stripped by recon).
            base_dir:      Parent directory for all run artifacts.
            phases:        Phases to execute, in order.
            safe_mode:     Apply lower-impact profile (phase/concurrency caps).
            operator_tag:  Identifier used in safe-mode request metadata/headers.

        Returns:
            Tuple of (run-directory path, phase results dict).
        """
        run_dir = self._build_run_dir(base_dir, target_domain)
        results: dict = {}
        effective_phases, dropped = self._effective_phases(phases, safe_mode=safe_mode)
        safe_operator = (operator_tag or SAFE_OPERATOR_TAG_DEFAULT).strip() or SAFE_OPERATOR_TAG_DEFAULT
        run_policy = {
            "safe_mode": safe_mode,
            "operator_tag": safe_operator if safe_mode else "",
            "requested_phases": ",".join(phases),
            "effective_phases": ",".join(effective_phases),
            "dropped_phases": ",".join(dropped),
            "scope_root": target_domain,
            "max_targets_per_phase": SAFE_MAX_TARGETS_PER_PHASE if safe_mode else "",
        }
        policy_path = run_dir / "run_policy.json"
        policy_path.write_text(json.dumps(run_policy, indent=2), encoding="utf-8")
        run_policy["path"] = str(policy_path)
        results["_run_policy"] = run_policy
        if safe_mode and dropped:
            self.print_warning_message(
                "Safe mode skipped high-noise phases",
                file_path=", ".join(dropped),
            )

        # Dispatch table — each entry receives the run_dir + previous results
        # so later phases can chain off earlier artifacts.
        dispatch = {
            PHASE_RECON: self._run_recon,
            PHASE_PROBE: lambda domain, workdir, prior: self._run_probe(
                domain,
                workdir,
                prior,
                safe_mode=safe_mode,
                operator_tag=safe_operator,
            ),
            PHASE_PORTS: self._run_ports,
            PHASE_SCREENSHOTS: lambda domain, workdir, prior: self._run_screenshots(
                domain,
                workdir,
                prior,
                safe_mode=safe_mode,
            ),
            PHASE_TAKEOVER: lambda domain, workdir, prior: self._run_takeover(
                domain,
                workdir,
                prior,
                safe_mode=safe_mode,
            ),
            PHASE_URLS: lambda domain, workdir, prior: self._run_urls(
                domain,
                workdir,
                prior,
                safe_mode=safe_mode,
            ),
            PHASE_VULNS: lambda domain, workdir, prior: self._run_vulns(
                domain,
                workdir,
                prior,
                safe_mode=safe_mode,
            ),
        }

        try:
            for phase in effective_phases:
                handler = dispatch.get(phase)
                if handler is None:
                    self.print_warning_message(f"Unknown phase '{phase}' — skipping.")
                    continue
                self.print_info_message(f"Running phase: {phase}")
                results[phase] = handler(target_domain, run_dir, results)
                self._print_phase_summary(phase, results[phase])
        finally:
            # Keep only final phase artifacts; remove helper files used during orchestration.
            self._cleanup_runtime_artifacts(run_dir, results)

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

    def _run_probe(
        self,
        _domain: str,
        run_dir: Path,
        results: dict,
        safe_mode: bool = False,
        operator_tag: str = SAFE_OPERATOR_TAG_DEFAULT,
    ) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon)
        if hosts is None:
            return {"json_path": None, "txt_path": None, "count": 0}
        scoped = self._build_scoped_hosts_file(
            hosts,
            target_domain=_domain,
            run_dir=run_dir,
            label="probe",
            safe_mode=safe_mode,
        )
        if scoped is None:
            return {"json_path": None, "txt_path": None, "count": 0, "scope_filtered": True}
        return self._http.probe(scoped, run_dir, safe_mode=safe_mode, operator_tag=operator_tag)

    def _run_ports(
        self,
        _domain: str,
        run_dir: Path,
        results: dict,
    ) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return (
            self._ports.scan(alive, run_dir)
            if alive
            else {"normal": None, "grepable": None, "count": 0}
        )

    def _run_screenshots(self, _domain: str, run_dir: Path, results: dict, safe_mode: bool = False) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return self._shots.capture(alive, run_dir, safe_mode=safe_mode) if alive else {"directory": None, "count": 0}

    def _run_takeover(self, _domain: str, run_dir: Path, results: dict, safe_mode: bool = False) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon) or recon.get("subdomains_file")
        if hosts is None:
            return {"output": None, "tool": None, "count": 0}
        scoped = self._build_scoped_hosts_file(
            hosts,
            target_domain=_domain,
            run_dir=run_dir,
            label="takeover",
            safe_mode=safe_mode,
        )
        if scoped is None:
            return {"output": None, "tool": None, "count": 0, "scope_filtered": True}
        return self._takeover.check(scoped, run_dir)

    def _run_urls(self, _domain: str, run_dir: Path, results: dict, safe_mode: bool = False) -> dict:
        recon = results.get(PHASE_RECON) or {}
        hosts = self._resolved_hosts_path(recon) or recon.get("subdomains_file")
        if hosts is None:
            return {"urls": None, "sensitive": None, "url_count": 0, "sensitive_count": 0}
        scoped = self._build_scoped_hosts_file(
            hosts,
            target_domain=_domain,
            run_dir=run_dir,
            label="urls",
            safe_mode=safe_mode,
        )
        if scoped is None:
            return {"urls": None, "sensitive": None, "url_count": 0, "sensitive_count": 0, "scope_filtered": True}
        return self._urls.collect(scoped, run_dir, safe_mode=safe_mode)

    def _run_vulns(self, _domain: str, run_dir: Path, results: dict, safe_mode: bool = False) -> dict:
        probe = results.get(PHASE_PROBE) or {}
        alive = probe.get("txt_path")
        return (
            self._vulns.scan(alive, run_dir, safe_mode=safe_mode)
            if alive
            else {"output": None, "total": 0, "severities": {}}
        )

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

    @staticmethod
    def _effective_phases(phases: tuple[str, ...], safe_mode: bool = False) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return (effective, dropped) phase tuples based on execution mode."""
        requested = tuple(dict.fromkeys(phases))
        if not safe_mode:
            return requested, tuple()
        allowed = set(SAFE_MODE_ALLOWED_PHASES)
        effective = tuple(phase for phase in requested if phase in allowed)
        dropped = tuple(phase for phase in requested if phase not in allowed)
        if not effective:
            effective = SAFE_MODE_ALLOWED_PHASES
        return effective, dropped

    @staticmethod
    def _in_scope_host(host: str, target_domain: str) -> bool:
        host_value = host.strip().lower().strip(".")
        root = target_domain.strip().lower().strip(".")
        if not host_value or not root:
            return False
        return host_value == root or host_value.endswith(f".{root}")

    def _build_scoped_hosts_file(
        self,
        source_file: Path,
        target_domain: str,
        run_dir: Path,
        label: str,
        safe_mode: bool = False,
    ) -> Path | None:
        """Filter target list to in-scope hosts and apply safe-mode caps."""
        if not source_file.exists():
            return None
        scoped: list[str] = []
        seen: set[str] = set()
        for raw in source_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            token = line.split()[0]
            host = (urlparse(token).hostname or token).strip().lower().strip(".")
            if not self._in_scope_host(host, target_domain):
                continue
            if host in seen:
                continue
            seen.add(host)
            scoped.append(host)

        if safe_mode and len(scoped) > SAFE_MAX_TARGETS_PER_PHASE:
            self.print_warning_message(
                f"Safe mode target cap reached for phase '{label}' "
                f"({len(scoped)} -> {SAFE_MAX_TARGETS_PER_PHASE})"
            )
            scoped = scoped[:SAFE_MAX_TARGETS_PER_PHASE]

        if not scoped:
            return None

        scoped_file = run_dir / f"{label}_scoped_targets.txt"
        scoped_file.write_text("\n".join(scoped) + "\n", encoding="utf-8")
        return scoped_file

    def _print_phase_summary(self, phase: str, result: dict) -> None:
        if result.get("missing") and result.get("skipped"):
            self.print_warning_message(
                f"Phase '{phase}' skipped — missing tool: {result['missing']}"
            )
            return
        if result.get("missing_optional"):
            self.print_warning_message(
                f"Phase '{phase}' partial — missing optional tool(s): {result['missing_optional']}"
            )
        # Compact one-line summary so the operator can monitor progress.
        keys_of_interest = ("count", "total", "url_count", "sensitive_count", "resolved_count")
        snippet = ", ".join(
            f"{k}={result[k]}" for k in keys_of_interest if k in result and result.get(k) is not None
        )
        if snippet:
            self.print_success_message(f"Phase '{phase}' done — {snippet}")
        else:
            self.print_success_message(f"Phase '{phase}' done.")

    def _cleanup_runtime_artifacts(self, run_dir: Path, results: dict) -> None:
        """Delete temporary files generated during phase chaining."""
        preserve_files: set[Path] = set()
        preserve_dir_roots: set[Path] = set()

        def collect_paths(node) -> None:
            if isinstance(node, dict):
                for value in node.values():
                    collect_paths(value)
                return
            if isinstance(node, (list, tuple, set)):
                for value in node:
                    collect_paths(value)
                return
            if isinstance(node, Path):
                candidate = node
            elif isinstance(node, str) and node.strip():
                candidate = Path(node)
            else:
                return

            if not candidate.exists():
                return
            try:
                resolved = candidate.resolve()
            except OSError:
                return
            try:
                resolved.relative_to(run_dir.resolve())
            except ValueError:
                return

            if resolved.is_dir():
                preserve_dir_roots.add(resolved)
            else:
                preserve_files.add(resolved)

        collect_paths(results)

        for file_path in run_dir.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                resolved = file_path.resolve()
            except OSError:
                continue
            if resolved in preserve_files:
                continue
            if any(root in resolved.parents for root in preserve_dir_roots):
                continue
            file_path.unlink(missing_ok=True)

        for dir_path in sorted(run_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if not dir_path.is_dir():
                continue
            try:
                resolved_dir = dir_path.resolve()
            except OSError:
                continue
            if resolved_dir in preserve_dir_roots:
                continue
            if any(resolved_dir in kept.parents for kept in preserve_files):
                continue
            try:
                dir_path.rmdir()
            except OSError:
                continue
