from pathlib import Path
import re
import os

# MOBILE ANALYSIS CONSTANTS

# Define regex patterns as raw strings for better readability and handling
IOS_FILE_SEARCH = r"hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView"
BEARER_REGEX = r"[^\w\d]+(basic|bearer)\s.+"
HARDCODED_REGEX = r'(\?access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)\w*(?:"\s*:\s*|\s*=).+'
HARDCODED_REGEX_2 = r"([^\w\d]+(to(_|\s)do|todo|note)\s|//|/\*|\*/).+"
BASE64_REGEX = r"(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}=|[a-zA-Z0-9\+\/]{2}==)"
IP_REGEX = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
DEEPLINKS_REGEX = r"\w+://[\w\-\.\@\:\/\?\=\%\&\#]+"
DEEPLINKS_REGEX_2 = r"\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)"


class MobileCommands:
    def __init__(self, shell_commands, filemanager, validator):
        self.commands = shell_commands()
        self.output_dir = ""
        self.file_type = ""
        self.filemanager = filemanager
        self.folder_name = ""
        self.file_name = ""
        self.validator = validator

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
        self.file_name = filename_without_ext
        if self.file_type == "apk":
            self.filemanager.create_folder(
                "Android", search_path="./output_directory/mobile"
            )
            self.output_dir = f"{base_dir}/Android"
            self.folder_name = f"{self.output_dir}/{filename_without_ext}"

            command = f"apktool d {package} -o {self.folder_name}"
            self.commands.run_os_commands(command)
            return self.folder_name

        elif self.file_type == "ipa":
            self.filemanager.create_folder(
                "iOS", search_path="./output_directory/mobile"
            )
            self.output_dir = f"{base_dir}/iOS"

        # 3. Clean up after all scans are complete

        # Inspect Files

    def find_files(self, appFolder, output):
        with open(output, "a") as output_file:
            for file in Path(appFolder).rglob("*"):
                if file.is_file():
                    command = f'rabin2 -zzzqq "{file}" 2>/dev/null | grep -Pi {IOS_FILE_SEARCH} | sort -uf'
                    result = self.commands.run_os_commands(command)
                    if result.stdour.strip():
                        output_file.write(f"{result.stdout}")

    def find_hardcoded_data(self, appFolder, output):
        with open(output, "a") as outfile:
            for somefile in Path(appFolder).rglob("*"):
                if somefile.is_file():
                    print(f"[+] Searching For hardcoded strings in File: \n{somefile}")
                    command = ["rabin2", "-zzzqq ", somefile]
                    regex_patterns = [BEARER_REGEX, HARDCODED_REGEX_2, HARDCODED_REGEX]
                    for pattern in regex_patterns:
                        # escaped_pattern = re.escape(pattern)
                        grep_command = f"{command} | grep -Pi {pattern}"
                        result = self.commands.run_os_commands(grep_command)
                        print(result.stdout)
                        # Sort and remove duplicates, then write to temp_file
                        #unique_lines = sorted(set(result.stdout.splitlines()))
                        # Check if theres data to write
                        # if result.returncode == 0 and result.stdout != "":
                        #     outfile.write("\n".join(unique_lines) + "\n")

    def get_base64_strings(self, folder, base_name):
        temp_file = Path(folder) / "strings.txt"
        base_64_file = Path(folder) / "base64.txt"
        output = f"{base_name}_base64_decoded.txt"

        if not self.validator.file_exists(temp_file):
            with open(temp_file, "w") as tempf:
                for file in Path(folder).rglob("*"):
                    if file.is_file():
                        command = ["rabin2", "-zzzqq ", file]
                        try:
                            result = self.commands.run_os_commands(command)
                            # Sort and remove duplicates, then write to temp_file

                            unique_lines = sorted(set(result.stdout.splitlines()))
                            print(f"[+] Creating temp file with following strings: \n{unique_lines}")
                            if result.stdout.strip():
                                tempf.write("\n".join(unique_lines) + "\n")
                        except Exception as error:
                            print(f"Error processing file {file} : {error}")

        if not self.validator.file_exists(base_64_file):
            with open(temp_file, "r") as temp_file:
                content = temp_file.read()

            base64_strings = re.findall(BASE64_REGEX, content)
            # Remove duplicates and write to base64 file
            unique_base64_strings = sorted(set(base64_strings))

            with open(base_64_file, "a") as f:
                f.write("\n".join(unique_base64_strings) + "\n")

            self.decode_base64(base_64_file, output)
        # Clean up temporary files
        try:
            os.remove(str(temp_file))
            os.remove(str(base_64_file))
        except Exception as e:
            print(f"Error removing temporary files: {e}")

    def decode_base64(self, base_64_file, output):
        with open(base_64_file, "r") as f, open(output, "a") as out_f:
            for string in f:
                string = string.strip()
                if string:  # Check if string is not empty
                    try:
                        command = f"echo '{string}' | base64 -d | grep -PI '[\s\S]+'"
                        decoded = self.commands.run_os_commands(command)

                        if decoded.stdout:
                            print(f"{string}\n{decoded.stdout}\n")
                            out_f.write(f"{string}\n{decoded.stdout}\n\n")
                    except Exception as e:
                        print(f"Error decoding base64 string {string}: {e}")
