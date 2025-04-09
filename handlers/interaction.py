import os
from argparse import RawTextHelpFormatter

from utils.shared import Validator
from handlers.network_handler import (NetworkHandler,
                                      get_network_interfaces)
from handlers.custom_parser import CustomArgumentParser, CustomHelp


def get_basename(fullpath):
    return os.path.basename(fullpath)


class InteractionHandler:
    """Class responsible for handling interactions with the user.
    Switches between different modes [interactive and arguments]
    """

    def __init__(self):
        self.argument_mode = False
        self.arguments = {}
        self.validator = Validator()

    def main(self):
        """Main Program"""
        parser = CustomArgumentParser(
            description="Penetest Framework: A modular penetration testing tool",
            add_help=False,
            formatter_class=RawTextHelpFormatter
        )  #
        # Verbosity flag
        # parser.add_argument(
        #     "-v",
        #     "--verbose",
        #     action="store_true",
        #     help="Show full help text when used with --help",
        # )

        parser.add_argument(
            "-M",
            dest="script_mode",
            choices=["interactive", "cli_args"],
            required=True,
            default="interactive",
            help=(
                "Select the mode to run the script with:\n"
                "  interactive: run with user interaction\n"
                "  cli_args: run with command-line arguments"
            ),
        )
        # Custom help function
        parser.add_argument(
            "-h",
            "--help",
            action=CustomHelp,
            help="Show this help message and exit",
        )

        # Add subparsers for different modules
        subparsers = parser.add_subparsers(
            dest="module",
            help="Module to run (mobile | internal | password | va | external)",
        )

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
            print("Running in interactive mode...")
            return
        elif _mode == "cli_args":
            # Module is required in arguments mode
            if not args.module:
                parser.error(
                    "the following arguments are required in arguments mode: MODULE"
                )
            self.argument_mode = True

            return self._run_modules(args, _module)

    def _run_modules(self, args, module):
        """Run the selected module with the provided arguments."""

        handler = {
            "mobile": self.handle_mobile_arguments,
            "internal": self.handle_internal_arguments,
            "password": self.handle_password_arguments,
            "va": self.handle_va_arguments,
            "external": self.handle_external_arguments,
        }
        self.arguments = handler[module](args, module)

    @staticmethod
    def _add_external_arguments(subparsers):
        """Handle External PT Arguments"""
        parser = subparsers.add_parser(
            "external", help="External Assessment Arguments")
        parser.add_argument(
            "-d",
            "--domain",
            required=True,
            type=str,
            help="Domain to test",
        )

    @staticmethod
    def _add_mobile_arguments(subparsers):
        """Handle Arguments for mobile assessments"""
        parser = subparsers.add_parser(
            "mobile", help="Mobile Assessment Arguments")
        parser.add_argument(
            "-P",
            "--path",
            type=str,
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
            type=str,
            choices=["nessus", "rapid"],
            help="Scanner used for analysis e.g( nessus | rapid )",
        )

        parser.add_argument(
            "-o",
            "--output",
            required=True,
            type=str,
            help="Output file for your Vulnerability analysis report",
        )
        parser.add_argument(
            "-P", "--path", required=True, type=str, help="Path to your scanned files"
        )

    @staticmethod
    def _add_password_arguments(subparsers):
        """Handle Password Arguments"""

        parser = subparsers.add_parser("password", help="Password Arguments")
        # run one action at a particular moment
        action_group = parser.add_mutually_exclusive_group(required=True)
        action_group.add_argument(
            "-t",
            "--test",
            action="store_true",
            help="Test the password against a protocol",
        )
        action_group.add_argument(
            "-g",
            "--generate",
            action="store_true",
            help="Generate a password list from cracked hashes",
        )

        parser.add_argument(
            "--ip",
            help="Target IP address - required for test",
        )
        parser.add_argument(
            "-d",
            "--domain",
            default=".",
            help="Target Domain - required for test",
        )
        parser.add_argument(
            "-p",
            "--pass_file",
            help="Password File - required for test",
        )
        parser.add_argument(
            "-c",
            "--crack",
            help="File with Cracked hashes - required for generate",
        )
        parser.add_argument(
            "-o",
            "--output",
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
            "-a",
            "--action",
            choices=["scan", "resume"],
            required=True,
            help="Mode of the internal PT (scan | resume)",
        )
        parser.add_argument(
            "-I", "--interface",
            required=True,
            choices=[iface
                     for iface in get_network_interfaces()
                     if NetworkHandler()._is_interface_active(iface)
                     and not iface.startswith(("br-", "docker", "veth", "lo"))],
            help="Interface to use with the script e.g (eth0, wlan0)"
        )
        mode_group = parser.add_argument_group("mode-specific arguments")
        mode_group.add_argument(
            "--ip",
            help="Target IP address with subnet (e.g., 10.1.1.1/24) - required for scan",
        )
        mode_group.add_argument(
            "-o",
            "--output",
            help="Output file for the scan results - required for scan",
        )
        mode_group.add_argument(
            "-r",
            "--resume_file",
            dest="resume",
            help="File with unresponsive hosts - required for resume",
        )
        mode_group.add_argument(
            "-m",
            "--mask",
            type=int,
            choices=range(1, 33),
            help="Subnet mask used for previous scan (0-32) - required for resume",
        )

    # Handlers for each module

    def handle_mobile_arguments(self, args, module):
        """Handle Mobile arguments"""
        path = args.path
        if not self.validator.isfile_and_exists(path):
            raise ValueError(f"File {path} does not exist")
            # Check if the file is an APK or IPA
        if not (
            self.validator.check_filetype(path, "apk")
            or self.validator.check_filetype(path, "ipa")
        ):
            # Valid mobile application file
            raise ValueError(f"File {path} is not a valid APK or IPA file")
        print(f"\n[-] Running Mobile Assessment on {path} application")
        return {"module": module, "full_path": path, "filename": get_basename(path)}

    def handle_external_arguments(self, args, module):
        """Handle External arguments"""

        if not self.validator.validate_domain(args.domain):
            raise ValueError(
                f"Domain {args.domain} is not valid. Ensure it is a valid domain name"
            )
        print(f"\n[-] Running External Assessment on {args.domain} domain")
        return {"module": module, "domain": args.domain}

    def handle_va_arguments(self, args, module):
        """Handle Vulnerability Assessment arguments"""
        scanner = args.scanner
        path = args.path
        file = args.output
        print(f"\n[-] Running {scanner.title()} Vulnerability Analysis ")

        if not self.validator.check_folder_exists(path):
            raise ValueError(
                f"Path {path} is not a valid directory. Ensure it exists and is a directory"
            )
        return {"module": module, "output_file": file, "scan_folder": path}

    def handle_password_arguments(self, args, module):
        """Handle Password arguments"""
        if args.test:
            # Testing password module
            ip = args.ip
            domain = args.domain
            pass_file = args.pass_file
            if not (ip and domain and pass_file):
                raise ValueError(
                    "For Test mode, --ip, --domain, and --pass_file are required"
                )
            if not self.validator.isfile_and_exists(pass_file):
                raise ValueError(f"File {pass_file} does not exist")
            if not self.validator.validate_ip_addr(ip):
                raise ValueError(
                    f"IP {ip} is not valid. Ensure it is a valid IP address"
                )

            # Add verbosity
            print(
                f"\n[-] Testing passwords from {get_basename(pass_file)} on Target IP: {ip} with {domain} domain"
            )

            return {
                "module": module,
                "action": "test",
                "target": ip,
                "domain": domain,
                "filename": "Successful_Logins.txt",
                "pass_file": pass_file,
            }
        elif args.generate:
            # Generate password list
            hashes = args.crack
            output = args.output
            dump = args.dump
            if not (hashes and output and dump):
                raise ValueError(
                    "For Generate mode, --crack, --output and --dump are required"
                )
            if not (
                self.validator.isfile_and_exists(hashes)
                and self.validator.isfile_and_exists(dump)
            ):
                raise ValueError(f"File {hashes} or {dump} does not exist")
            print(
                f"\n[-] Generating Password List from {hashes} and {dump} files")
            return {
                "module": module,
                "hashes": hashes,
                "filename": output,
                "dumps": dump,
                "action": "generate",
            }

    def handle_internal_arguments(self, args, module):
        """Handle Internal PT arguments"""
        action = args.action
        interface = args.interface
        print(interface)
        if action == "scan":
            # scan network
            ip_cidr = args.ip
            output = args.output
            if not (ip_cidr and output):
                raise ValueError(
                    "For Scan mode, --ip and --output are required")
            if not self.validator.validate_ip_and_cidr(ip_cidr):
                raise ValueError(
                    f"IP {ip_cidr} is not valid. Ensure it is a valid IP address with CIDR notation"
                )
            print(f"\n[-] Running Internal PT Scan on {ip_cidr} network")
            return {
                "module": module,
                "action": action,
                "subnet": ip_cidr,
                "output": output,
                "interface": interface
            }
        elif action == "resume":
            # Resume scan
            resume_file = args.resume
            mask = args.mask
            if not (resume_file and mask):
                raise ValueError(
                    "For resume mode, --resume and --mask are required")
            if not self.validator.isfile_and_exists(resume_file):
                raise ValueError(f"File {resume_file} does not exist")
            print(
                f"\n[-] Resuming previous scan from File: {get_basename(resume_file)} on /{mask} network"
            )
            return {
                "module": module,
                "action": action,
                "resume_file": resume_file,
                "mask": mask,
                "interface": interface
            }
