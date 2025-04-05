import argparse


class InteractionHandler:
    """Class responsible for handling interactions with the user.
    Switches between different modes [interactive and arguments]
    """

    def __init__(self):
        pass
        self.HEADLINE = "Usage: script_name.py [ --(interactive | arguments | help) ]"
        self.argument_mode = False

    def main(self):
        """Main Program"""
        parser = argparse.ArgumentParser(
            description="Handle different modes of the script.",
            usage=self.HEADLINE)
        parser.add_argument("--script-mode",
                            metavar="script_mode",
                            choices=["interactive", "arguments"],
                            type=str,
                            default="interactive",
                            required=True,
                            help="Choose the mode to run the script. (interactive | arguments)")

        # Add subparsers for different modules
        subparsers = parser.add_subparsers(
            dest="module", help="Module to run (mobile | internal | password | va | external)")
        subparsers.required = True  # Ensure a module-specific command is provided

        self._add_mobile_arguments(subparsers)
        self._add_internal_arguments(subparsers)
        self._add_password_arguments(subparsers)
        self._add_va_arguments(subparsers)
        self._add_external_arguments(subparsers)

        args = parser.parse_args()
        _mode = args.script_mode
        _module = args.module
        print(f"Selected script mode: {_mode}")
        if _mode == "interactive":
            pass
        elif _mode == "arguments":
            self.argument_mode = True
            return self._run_modules(args, _module)

    def _run_modules(self, args, module):
        """Run the selected module with the provided arguments."""
        print(args, module)
        handler = {
            "mobile": self.handle_mobile_arguments,
            "internal": self.handle_internal_arguments,
            "password": self.handle_password_arguments,
            "va": self.handle_va_arguments,
            "external": self.handle_external_arguments
        }
        return handler[module](args)

    @staticmethod
    def _add_external_arguments(subparsers):
        """Handle External PT Arguments"""
        pass

    @staticmethod
    def _add_mobile_arguments(subparsers):
        """Handle Arguments for mobile assessments """
        parser = subparsers.add_parser(
            "mobile", help="Mobile Assessment Arguments")
        parser.add_argument(
            "-P", "--path",
            required=True,
            help="Path to the mobile application file",
        )

    @staticmethod
    def _add_va_arguments(subparsers):
        """Handle Vulnerability Analysis Arguments"""
        parser = subparsers.add_parser(
            "va", help="Vulnerability Analysis Arguments")
        parser.add_argument(
            "-s",
            "--scanner",
            required=True,
            choices=["nessus", "rapid"],
            help="Scanner used for analysis e.g( nessus | rapid )"
        )

        parser.add_argument(
            "-o",
            "--output",
            required=True,
            help="Output file for your Vulnerability analysis report"
        )
        parser.add_argument(
            "-P",
            "--path",
            required=True,
            help="Path to your scanned files"
        )

    @staticmethod
    def _add_password_arguments(subparsers):
        """Handle Password Arguments"""

        parser = subparsers.add_parser("password", help="Password Arguments")
        action_group = parser.add_mutually_exclusive_group(required=True)
        action_group.add_argument(
            "-t", "--test",
            action="store_true",
            help="Test the password against a protocol",
        )
        action_group.add_argument(
            "-g", "--generate",
            action="store_true",
            help="Generate a password list from cracked hashes",
        )
        parser.add_argument(
            "--ip",
            help="Target IP address - required for test",
        )
        parser.add_argument(
            "-d", "--domain",
            help="Target Domain - required for test",
        )
        parser.add_argument(
            "-p", "--pass_file",
            help="Password File - required for test",
        )
        parser.add_argument(
            "-c", "--crack",
            help="File with Cracked hashes - required for generate",
        )
        parser.add_argument(
            "-o", "--output",
            help="Output file - required for generate",
        )
        parser.add_argument(
            "--dump",
            help="NTDS Dump file - required for generate",
        )

    @staticmethod
    def _add_internal_arguments(subparsers):
        """Handle Internal PT Arguments"""
        parser = subparsers.add_parser(
            "internal", help="Internal PT arguments")
        parser.add_argument(
            "-M", "--mode",
            choices=["scan", "resume"],
            required=True,
            help="Mode of the internal PT (scan | resume)",
        )
        mode_group = parser.add_argument_group("mode-specific arguments")
        mode_group.add_argument(
            "--ip",
            help="Target IP address with subnet (e.g., 10.1.1.1/24) - required for scan",
        )
        mode_group.add_argument(
            "-o", "--output",
            help="Output file for the scan results - required for scan",
        )
        mode_group.add_argument(
            "-r", "--resume",
            help="File with unresponsive hosts - required for resume",
        )
        mode_group.add_argument(
            "-m", "--mask",
            type=int,
            choices=range(0, 33),
            help="Subnet mask used for previous scan (0-32) - required for resume",
        )

    # Handlers for each module

    @staticmethod
    def handle_mobile_arguments(args):
        """Handle Mobile arguments"""
        print(f"Handling Mobile arguments: {args}")

    @staticmethod
    def handle_external_arguments(args):
        """Handle External arguments"""
        print(f"Handling External arguments: {args}")

    @staticmethod
    def handle_va_arguments(args):
        """Handle Vulnerability Assessment arguments"""
        print(f"Handling Vulnerability Assessment arguments: {args}")

    @staticmethod
    def handle_password_arguments(args):
        """Handle Password arguments"""
        print(f"Handling Password arguments: {args}")

    @staticmethod
    def handle_internal_arguments(args):
        """Handle Internal PT arguments"""
        print(f"Handling Internal PT arguments: {args}")


if __name__ == "__main__":
    interaction = InteractionHandler()
    interaction.main()
