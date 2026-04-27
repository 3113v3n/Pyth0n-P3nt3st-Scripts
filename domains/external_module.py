"""
external_module.py — External assessment domain controller.

Wires the ExternalPipeline (subdomain enumeration → HTTP probing → screenshots
→ subdomain takeover → URL collection → nuclei vulnerability scan → port scan)
to the framework's report writer and AI assistant.
"""

from __future__ import annotations

from pathlib import Path

from handlers.messages import DisplayHandler
from utils.external import ExternalPipeline, ExternalReport
from utils.external.external_constants import DEFAULT_PHASES, SAFE_OPERATOR_TAG_DEFAULT
from utils.shared.decorators import CustomDecorators


class ExternalAssessment(DisplayHandler):
    """Drive an external penetration test against a target domain."""

    def __init__(self) -> None:
        super().__init__()
        self.target_domain = ""
        self.phases: tuple[str, ...] = DEFAULT_PHASES
        self.safe_mode = False
        self.operator_tag = SAFE_OPERATOR_TAG_DEFAULT
        self.base_dir: Path | None = None
        self.debug = False
        self.pipeline = ExternalPipeline(debug=self.debug)
        self.reporter = ExternalReport()
        self.decorator = CustomDecorators()
        # [AI] PentestFramework.initialize_classes() injects the shared instance.
        self.ai = None

    def initialize_variables(self, variables: dict) -> None:
        """Populate runtime state from the user/CLI handler payload.

        Args:
            variables: Mapping with at minimum {"target_domain", "base_dir"}.
                       Optional keys:
                         - "phases" (tuple/list of phase names)
                         - "safe_mode" (bool)
                         - "operator_tag" (str)
        """
        self.target_domain = variables["target_domain"]
        base_dir = variables.get("base_dir")
        if base_dir is None:
            raise ValueError("ExternalAssessment requires 'base_dir' in variables")
        self.base_dir = Path(base_dir)

        configured = variables.get("phases")
        if configured:
            self.phases = tuple(configured)
        self.safe_mode = bool(variables.get("safe_mode", False))
        raw_operator = str(variables.get("operator_tag", "") or "").strip()
        self.operator_tag = raw_operator or SAFE_OPERATOR_TAG_DEFAULT

    def run(self) -> dict:
        """Execute all configured phases and write the consolidated report.

        Returns:
            Dictionary describing the run: report path, run directory, phase
            results, and the AI summary text (if enabled).
        """
        if not self.target_domain or self.base_dir is None:
            raise RuntimeError("ExternalAssessment.initialize_variables() must run first.")

        self.print_info_message(f"Starting external assessment on {self.target_domain}")

        run_dir, results = self.pipeline.run(
            target_domain=self.target_domain,
            base_dir=self.base_dir,
            phases=self.phases,
            safe_mode=self.safe_mode,
            operator_tag=self.operator_tag,
        )

        ai_summary = self._maybe_ai_summary(results)
        run_policy = results.get("_run_policy") if isinstance(results, dict) else None
        report_path = self.reporter.write(
            target_domain=self.target_domain,
            run_dir=run_dir,
            phase_results=results,
            ai_summary=ai_summary,
            run_policy=run_policy if isinstance(run_policy, dict) else None,
        )

        self.print_success_message(
            message="External assessment report written to:",
            extras=f"\n{report_path}",
        )
        return {
            "report": report_path,
            "run_dir": run_dir,
            "phases": results,
            "ai_summary": ai_summary,
        }

    def _maybe_ai_summary(self, phase_results: dict) -> str | None:
        if not (self.ai and getattr(self.ai, "enabled", False)):
            return None
        try:
            return self.ai.analyze_external_findings(self.target_domain, phase_results)
        except Exception as error:
            self.print_warning_message(f"AI summary unavailable: {error}")
            return None
