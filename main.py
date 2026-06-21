import sys
from pathlib import Path

from handlers.package_handler import PackageHandler
from handlers.framework_assessment_mixin import FrameworkAssessmentMixin
from handlers.framework_core_mixin import FrameworkCoreMixin
from handlers.framework_runtime_mixin import FrameworkRuntimeMixin
from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.shared.commands import Commands


class PentestFramework(
    FrameworkCoreMixin,
    FrameworkAssessmentMixin,
    FrameworkRuntimeMixin,
    ScreenHandler,
):
    """Main framework class composed from lean, reusable mixins."""

    def __init__(self):
        super().__init__()
        # Refactor note: state remains in the root class so mixins stay stateless.
        self.ai = None
        self.use_ai = False
        self.classes = self.initialize_classes()
        self.exit_menu = False
        self.debug = False
        self.cmd_args = False
        self.os = ""
        self.strict_project_mode = True
        self.auto_relax_on_strict = False


def main():
    """Entry point of the program."""
    from handlers.interaction import InteractionHandler

    if not PackageHandler.ensure_project_virtualenv():
        DisplayHandler.print_error_message("Critical error: project virtualenv bootstrap failed")
        sys.exit(1)

    _interaction = InteractionHandler()
    try:
        _interaction.main()
        framework = PentestFramework()
        framework.strict_project_mode = bool(
            _interaction.runtime_options.get("strict_project_mode", True)
        )
        framework.auto_relax_on_strict = bool(
            _interaction.runtime_options.get("auto_relax_on_strict", False)
        )
        Commands.configure_policy(
            strict_project_mode=framework.strict_project_mode,
            project_root=Path(__file__).resolve().parent,
        )

        # Keep CLI behavior identical after refactor: --no-ai toggles the shared AI instance.
        if not _interaction.arguments.get("use_ai", True):
            framework.use_ai = False

        use_cmdline_args = _interaction.argument_mode
        if not use_cmdline_args:
            framework.run_program()
            return

        _interaction.arguments["use_args"] = use_cmdline_args
        framework.run_program_interactively(_interaction.arguments)
    except Exception as error:
        DisplayHandler.print_error_message("Critical error", exception_error=error)
        sys.exit(1)


if __name__ == "__main__":
    main()
