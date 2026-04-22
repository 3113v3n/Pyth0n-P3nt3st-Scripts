import os

from utils.mobile import MobileCommands


class MobileAssessment(MobileCommands):
    # class will be responsible for all mobile operations
    def __init__(self) -> None:
        super().__init__()  # commands: MobileCommands
        self.package_name = ""
        self.package_path = ""
        # [AI] Set by PentestFramework.initialize_classes(); None means disabled
        self.ai = None

    @classmethod
    def reset_class_states(cls):
        """Reset the states of the class"""
        cls.package_name = ""
        cls.package_path = ""

    def initialize_variables(self, data):

        # Sets user provided values
        self.package_name = data["filename"]  # application filename
        self.package_path = data["full_path"]  # fullpath to the application

    def _inspect_files(self, test_domain: str, operating_system: str):
        """Execute the mobile application testing module
        :param test_domain: Test domain
        :param operating_system: Running Operating system"""
        try:
            self.inspect_application_files(
                application=self.package_path,
                test_domain=test_domain,
                operating_system=operating_system
            )

            # [AI] After scanning, surface high-signal findings to Claude.
            # The hardcoded-strings output file is written to mobile_output_dir.
            if self.ai and self.ai.enabled:
                findings = self._collect_mobile_findings()
                if findings:
                    ai_analysis = self.ai.analyze_mobile_findings(findings)
                    self.print_success_message(
                        message="AI Findings Analysis:", extras=f"\n{ai_analysis}")

            self.print_total_time(f"Total analysis time for {self.package_name}")
        finally:
            self.reset_total_time()

    def _collect_mobile_findings(self) -> dict:
        """Read output files produced by the mobile scan and return a findings dict.

        Returns:
            Dictionary with category keys mapping to lists of string findings.
            Empty if no output directory is set or no files exist.
        """
        findings: dict = {}
        output_dir = getattr(self, "mobile_output_dir", None)
        if not output_dir or not os.path.isdir(output_dir):
            return findings

        # Map output file suffixes to category keys expected by PentestAI.
        # Keep case-insensitive matching for backward compatibility.
        category_map = {
            "_hardcoded.txt": "hardcoded",
            "_urls.txt": "urls",
            "_ips.txt": "ips",
            "_base64.txt": "base64",
            "_integrity_findings.txt": "integrity",
        }
        basename = getattr(self, "file_name", "")
        platform = "android" if getattr(self, "file_type", "").lower() == "apk" else "ios"
        prefix = f"{output_dir}/{basename}_{platform}"

        # Build a case-insensitive index of files once.
        file_lookup = {}
        for entry in os.listdir(output_dir):
            file_lookup[entry.lower()] = os.path.join(output_dir, entry)

        for suffix, category in category_map.items():
            target_name = f"{basename}_{platform}{suffix}".lower()
            path = file_lookup.get(target_name)
            if not path:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = [ln.strip() for ln in fh if ln.strip()]
                if lines:
                    findings[category] = lines
            except OSError:
                pass
        return findings

    # Install web proxies cert
    # 1. Take filepath to .der

    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
