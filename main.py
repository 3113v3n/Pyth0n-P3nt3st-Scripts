import sys

from handlers.package_handler import PackageHandler
from handlers.framework_assessment_mixin import FrameworkAssessmentMixin
from handlers.framework_core_mixin import FrameworkCoreMixin
from handlers.framework_runtime_mixin import FrameworkRuntimeMixin
from handlers.screen import ScreenHandler


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
        self.use_ai = True
        self.classes = self.initialize_classes()
        self.exit_menu = False
        self.debug = False
        self.cmd_args = False
        self.os = ""


def main():
    """Entry point of the program."""
    from handlers.interaction import InteractionHandler

    PackageHandler.ensure_project_virtualenv()

    _interaction = InteractionHandler()
    try:
        _interaction.main()
        framework = PentestFramework()

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
        print(f"\n[!] Critical error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
