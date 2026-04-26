"""
interaction.py — CLI argument parsing and module selection.

Startup hardening: module imports for network/file handlers are now lazy so
argument parsing can run even when optional runtime dependencies are missing.

Naming: Removed the pointless os.path.basename() wrapper — os.path.basename() is
called directly at the two call sites instead.
"""

import os
from argparse import RawTextHelpFormatter

from utils.shared.validators import Validator
from handlers.custom_parser import CustomArgumentParser, CustomHelp


class InteractionHandler:
    """Class responsible for handling interactions with the user.
    Switches between different modes [interactive and arguments]
    """

    def __init__(self):
        self.argument_mode = False
        self.arguments = {}
        self.validator = Validator()
        self.filehandler = None

    def main(self):
        """Main Program"""
        parser = CustomArgumentParser(
            description="Pentest Framework: A modular penetration testing tool",
            add_help=False,
            formatter_class=RawTextHelpFormatter
        )  #
        # Verbosity flag
        # parser.add_argument(
        #     "-v",
        #     "--verbose",
        #     action="store_true",
        #     help="Show full help text when used with --help")

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

        # [AI] Disable AI analysis features at runtime without unsetting the key
        parser.add_argument(
            "--no-ai",
            dest="use_ai",
            action="store_false",
            default=True,
            help="Disable AI-powered analysis (default: enabled when ANTHROPIC_API_KEY is set)",
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
        # [AI] Forward the --no-ai flag so main() can disable the AI instance
        self.arguments["use_ai"] = getattr(args, "use_ai", True)

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
            help=(
                "Path to an APK/IPA file or a directory containing APK/IPA files. "
                "When a directory is provided in cli_args mode, all discovered apps are scanned."
            ),
        )
        parser.add_argument(
            "--scan-mode",
            choices=["single", "all"],
            default="all",
            help=(
                "Directory handling mode in cli_args: 'all' scans all APK/IPA files, "
                "'single' scans one app (requires a single file path, or a directory with exactly one app)."
            ),
        )
        parser.add_argument(
            "--taxonomy",
            choices=["none", "masvs", "mastg", "both"],
            default="both",
            help=(
                "Optional static-report taxonomy tagging. "
                "'masvs' adds MASVS tags, 'mastg' adds MASTG tags, and 'both' adds both."
            ),
        )
        parser.add_argument(
            "--taxonomy-profile",
            choices=["strict", "balanced", "aggressive"],
            default="balanced",
            help=(
                "Granularity profile for taxonomy mapping. "
                "'strict' maps only high-confidence tags, 'balanced' blends precision/coverage, "
                "and 'aggressive' adds broader inferred tags."
            ),
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
        # Keep parser import-light by querying interfaces directly from netifaces.
        interface_choices = []
        interface_help = "Interface to use with the script e.g (eth0, wlan0)"
        try:
            import netifaces

            interface_choices = [
                iface
                for iface in netifaces.interfaces()
                if not iface.startswith(("br-", "docker", "veth", "lo"))
            ]
        except ModuleNotFoundError as error:
            interface_help = (
                "Interface to use with the script e.g (eth0, wlan0). "
                f"Interface auto-discovery disabled (missing dependency: {error.name})."
            )
        except Exception as error:
            # Some restricted environments raise EPERM when listing interfaces.
            # Keep parser construction alive so unrelated modules (e.g. mobile)
            # can still run in cli_args mode.
            interface_help = (
                "Interface to use with the script e.g (eth0, wlan0). "
                f"Auto-discovery unavailable in this environment: {error}"
            )

        interface_kwargs = {
            "required": True if interface_choices else False,
            "help": interface_help,
        }
        if interface_choices:
            interface_kwargs["choices"] = interface_choices

        parser.add_argument("-I", "--interface", **interface_kwargs)
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
        scan_mode = args.scan_mode
        taxonomy = args.taxonomy
        taxonomy_profile = args.taxonomy_profile

        # CLI behavior: if directory is provided, scan all APK/IPA files by default.
        if self.validator.check_folder_exists(path):
            if self.filehandler is None:
                from handlers.file_handler import FileHandler  # Lazy import
                self.filehandler = FileHandler()

            self.filehandler.files = []
            self.filehandler.find_files(path)
            file_collection = self.filehandler._get_file_collections()
            applications = sorted(
                file_collection["applications"],
                key=lambda app: app["filename"].lower(),
            )
            if not applications:
                raise ValueError(
                    f"No APK/IPA files found in directory: {path}"
                )

            if scan_mode == "single":
                if len(applications) > 1:
                    raise ValueError(
                        "Scan mode 'single' requires a single APK/IPA file path. "
                        "The provided directory contains multiple applications."
                    )
                app = applications[0]
                print(f"\n[-] Running Mobile Assessment on {app['full_path']} application")
                return {
                    "module": module,
                    "scan_mode": "single",
                    "taxonomy": taxonomy,
                    "taxonomy_profile": taxonomy_profile,
                    "full_path": app["full_path"],
                    "filename": app["filename"],
                }

            print(
                f"\n[-] Running Mobile Assessment on all applications in {path} "
                f"({len(applications)} found)"
            )
            return {
                "module": module,
                "scan_mode": "all",
                "taxonomy": taxonomy,
                "taxonomy_profile": taxonomy_profile,
                "source_path": path,
                "applications": applications,
            }

        if not self.validator.isfile_and_exists(path):
            raise ValueError(f"Path {path} does not exist")

        # Check if the file is an APK or IPA
        if not (
            self.validator.check_filetype(path, "apk")
            or self.validator.check_filetype(path, "ipa")
        ):
            raise ValueError(f"File {path} is not a valid APK or IPA file")

        print(f"\n[-] Running Mobile Assessment on {path} application")
        return {
            "module": module,
            "scan_mode": "single",
            "taxonomy": taxonomy,
            "taxonomy_profile": taxonomy_profile,
            "full_path": path,
            "filename": os.path.basename(path),
        }

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
        if self.filehandler is None:
            from handlers.file_handler import FileHandler  # Lazy import
            self.filehandler = FileHandler()

        # ENSURE THE FILES ARE OF VALID FILETYPES [.CSV,.XLSX,.XLX]
        self.filehandler.find_files(path)  # generates a list of all files
        file_collection = self.filehandler._get_file_collections()
        valid_files = self.filehandler._filter_files_by_extension(
            file_collection, extension="both")

        return {"module": module,
                "output_file": file,
                "scan_files": valid_files}

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
                f"\n[-] Testing passwords from {os.path.basename(pass_file)} on Target IP: {ip} with {domain} domain"
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
            # Generate a password list
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
        if not interface:
            raise ValueError(
                "No network interface provided. Use -I/--interface explicitly "
                "(interface auto-discovery may be restricted in this environment)."
            )
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
                f"\n[-] Resuming previous scan from File: {os.path.basename(resume_file)} on /{mask} network"
            )
            return {
                "module": module,
                "action": action,
                "resume_file": resume_file,
                "mask": mask,
                "interface": interface
            }
