# import re
# MOBILE ANALYSIS CONSTANTS

IOS_FILE_SEARCH = r"hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView"
BEARER_REGEX = r"[^\w\d]+(basic|bearer)\ .+"
HARDCODED_REGEX = r"(access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)\w*(?:\"\ *\:|\ *\=).+"
HARDCODED_REGEX_2 = r"([^\w\d]+(to(\_|\ )do|todo|note)\ |\/\/|\/\*|\*\/).+"
BASE64_REGEX = r"(?:([a-zA-Z0-9\+\/]){4})*(?:(?1){4}|(?1){3}\=|(?1){2}\=\=)"
IP_REGEX = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"


class MobileCommands:
    def __init__(self, shell_commands, filemanager):
        self.commands = shell_commands()
        self.output_dir = ""
        self.file_type = ""
        self.filemanager = filemanager
        self.folder_name = ""

    def push_certs(self, certificate):
        self.commands.run_os_commands(f"adb push {certificate} /storage/emulated/0/")

    def pull_package_with_keyword(self, keyword):
        pkg_cmd = f"adb shell pm list packages '{keyword}'|head -n 1|cut -d ':' -f2"
        pkg = self.commands.get_process_output(pkg_cmd).strip()

        if pkg:
            # Get the APK path
            path_cmd = f"adb shell pm path {pkg} | cut -d ':' -f2 | grep 'base.apk'"
            apk_path = self.commands.get_process_output(path_cmd).strip()

            if apk_path:
                # pull the APK
                pull_cmd = f"adb pull {apk_path} ./"
                self.commands.run_os_commands(pull_cmd)
                print(f"APK pulled successfully: {apk_path}")
            else:
                print("APK path not found.")
        else:
            print("Package not found")

    # Decompile APk
    def decompile_application(self, package):
        """
        Takes an apk / ios file and decompiles them using
        apktool or unzip respectively

        """
        # 1. decompile using apk tool
        # 2. save the decompiled file to output directory
        base_dir = self.filemanager.output_directory
        self.file_type = self.filemanager.get_file_extension(package)  # ipa / apk
        filename_without_ext = self.filemanager.get_filename_without_extension(package)
        if self.file_type == "apk":
            self.filemanager.create_folder(
                "Android", search_path="./output_directory/mobile"
            )
            self.output_dir = f"{base_dir}/Android"
            self.folder_name = f"{self.output_dir}/{filename_without_ext}"

            command = f"apktool d {package} -o {self.folder_name}"
            self.commands.run_os_commands(command)
        elif self.file_type == "ipa":
            self.filemanager.create_folder(
                "iOS", search_path="./output_directory/mobile"
            )
            self.output_dir = f"{base_dir}/iOS"
           
        # 3. Clean up after all scans are complete

    # Inspect Files
