import argparse


class InteractionHandler:
    """Class responsible for handling interactions with the user.
    Switches between different modes [interactive and arguments]
    """
    # {os.path.basename(__file__)}

    def __init__(self):
        pass
        self.HEADLINE = "Usage: main.py [ --(interactive | arguments | help) ]"
        self.argument_mode = False

    def main(self):
        """Main Program"""
        parser = argparse.ArgumentParser(
            description="Handle different modes of the script.",
            usage=self.HEADLINE)
        parser.add_argument("--script-mode",
                            metavar="script_mode",
                            choices=["interactive", "arguments"],
                            required=True,
                            default="interactive",
                            help="Choose the mode to run the script. (interactive | arguments)")

        # Add subparsers for different modules
        subparsers = parser.add_subparsers(
            dest="module", help="Module to run (mobile | internal | password | va | external)")

        self._add_mobile_arguments(subparsers)
        self._add_internal_arguments(subparsers)
        self._add_password_arguments(subparsers)
        self._add_va_arguments(subparsers)
        self._add_external_arguments(subparsers)

        args = parser.parse_args()
        _mode = args.script_mode
        _module = args.module

        if _mode == "interactive":
            # Run Script with user interaction
            self.argument_mode = False
            return
        elif _mode == "arguments":
            # Module is required in arguments mode
            if not args.module:
                parser.error(
                    "the following arguments are required in arguments mode: module")
            self.argument_mode = True

            return self._run_modules(args, _module)

    def _run_modules(self, args, module):
        """Run the selected module with the provided arguments."""

        handler = {
            "mobile": self.handle_mobile_arguments,
            "internal": self.handle_internal_arguments,
            "password": self.handle_password_arguments,
            "va": self.handle_va_arguments,
            "external": self.handle_external_arguments
        }
        return handler[module](args, module)

    @staticmethod
    def _add_external_arguments(subparsers):
        """Handle External PT Arguments"""
        parser = subparsers.add_parser(
            "external", help="External Assessment Arguments")
        parser.add_argument(
            "-d", "--domain",
            required=True,
            help="Domain to test",
        )

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
    def handle_mobile_arguments(args, module):
        """Handle Mobile arguments"""
        path = args.path
        print(f"\nRunning Mobile Assessment on application {path}")
        # TODO: Validate file exists and is one of [ipa or apk]
        return {
            "module": module,
            "apk_path": path
        }

    @staticmethod
    def handle_external_arguments(args, module):
        """Handle External arguments"""

        print(f"Handling External arguments: {args} on module {module}")
        return {
            "module": module,
            "domain": args.domain
        }

    @staticmethod
    def handle_va_arguments(args, module):
        """Handle Vulnerability Assessment arguments"""
        scanner = args.scanner
        path = args.path
        file = args.output
        print(f"\nRunning {scanner.title()} Vulnerability Analysis ")
        # TODO: Validate input is a folder
        return {
            "module": module,
            "output_file": file,
            "scan_folder": path
        }

    @staticmethod
    def handle_password_arguments(args, module):
        """Handle Password arguments"""
        # TODO :1 Validate ip address
        # TODO :2 Validate pass_file exists
        # TODO :3 Validate hash file
        # TODO :4 Validate Dump file exists
        if args.test:
            # Testing password module
            ip = args.ip
            domain = args.domain
            pass_file = args.pass_file
            if not (ip and domain and pass_file):
                raise ValueError(
                    "For Test mode, --ip, --domain, and --pass_file are required")
            print(
                f"\nPassword test with IP: {ip}, \ndomain: {domain}, \npass_file: {pass_file}")
            return {
                "module": module,
                "action": "test",
                "target_ip": ip,
                "domain": domain,
                "pass_file": pass_file}
        elif args.generate:
            # Generate password list
            hashes = args.crack
            output = args.output
            dump = args.dump
            if not (hashes and output and dump):
                raise ValueError(
                    "For Generate mode, --crack, --output and --dump are required")
            print(
                f"\nGenerate Password list using \nCracked hashes: {hashes} \nand Dump file: {dump}")
            return {
                "module": module,
                "hashes": hashes,
                "out_file": output,
                "dump": dump
            }

    @staticmethod
    def handle_internal_arguments(args, module):
        """Handle Internal PT arguments"""
        # TODO :1 validate ip_cidr is of a particular pattern [IP/mask]
        # TODO :2 Validate resume_file exists
        mode = args.scan
        if mode == "scan":
            # scan network
            ip_cidr = args.ip
            output = args.output
            if not (ip_cidr and output):
                raise ValueError(
                    "For Scan mode, --ip and --output are required")
            print(f"\nScanning {ip_cidr} network")
            return {
                "module": module,
                "mode": mode,
                "ip": ip_cidr,
                "output": output
            }
        elif mode == "resume":
            # Resume scan
            resume_file = args.resume
            mask = args.mask
            if not (resume_file and mask):
                raise ValueError(
                    "For resume mode, --resume and --mask are required")
            print(f"\nResuming scan on /{mask} network")
            return {
                "module": module,
                "mode": mode,
                "resume_file": resume_file,
                "mask": mask
            }


if __name__ == "__main__":
    interaction = InteractionHandler()
    interaction.main()
