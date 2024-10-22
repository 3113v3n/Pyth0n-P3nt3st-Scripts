from pathlib import Path
import re


class MobileCommands:
    def __init__(self, shell_commands, filemanager, validator, color, configs):
        self.commands = shell_commands()
        self.output_dir = ""
        self.file_type = ""
        self.filemanager = filemanager
        self.configs = configs
        self.folder_name = ""
        self.file_name = ""
        self.validator = validator
        self.color = color
        self.all_urls = []
        self.all_ips = []
        self.url_count = 0
        self.file_count = 0
        self.temp_data = ""
        self.temp_base64_data = ""

    def push_certs(self, certificate):
        self.commands.run_os_commands(f"adb push {certificate} /storage/emulated/0/")

    def pull_package_with_keyword(self, keyword):
        pkg_cmd = (
            f"adb shell pm list packages | grep '{keyword}'|head -n 1|cut -d ':' -f2"
        )
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
        self.file_name = self.validator.remove_spaces(filename_without_ext)

        if self.file_type == "apk":
            self.filemanager.create_folder(
                "Android", search_path="./output_directory/mobile"
            )
            self.output_dir = f"{base_dir}/Android"
            self.folder_name = f"{self.output_dir}/{filename_without_ext}"
            self.folder_name = self.validator.remove_spaces(self.folder_name)

            if not self.validator.check_folder_exists(self.folder_name):
                print(f"\n Decompiling the {self.file_name} application ...")
                command = f"apktool d '{package}' -o {self.folder_name}"
                self.commands.run_os_commands(command)
                print("Decompiling successful")
            return self.folder_name

        elif self.file_type == "ipa":
            self.filemanager.create_folder(
                "iOS", search_path="./output_directory/mobile"
            )

            self.output_dir = f"{base_dir}/iOS"
            self.folder_name = f"{self.output_dir}/{self.file_name}"

            if not self.validator.check_folder_exists(self.folder_name):
                print(f"Decompiling {self.file_name} ...")
                command = f"unzip '{package}' -d {self.folder_name}"
                try:
                    print(f"Running command: {command}")
                    result = self.commands.run_os_commands(command)
                    if result.returncode == 0:
                        print("Decompiling successful")
                    else:
                        raise FileNotFoundError

                except (Exception, FileNotFoundError) as error:
                    print(f"Error during unzip: {error}")

            return self.folder_name

        # 3. Clean up after all scans are complete

        # Inspect Files

    def find_files(self, appFolder, output):
        with open(output, "a") as output_file:
            for file in Path(appFolder).rglob("*"):
                if file.is_file():
                    command = f'rabin2 -zzzqq "{file}" 2>/dev/null | grep -Pi {self.configs.IOS_FILE_SEARCH} | sort -uf'
                    result = self.commands.run_os_commands(command)
                    if result.stdour.strip():
                        output_file.write(f"{result.stdout}")

    def find_hardcoded_data(self, appFolder, output):

        with open(output, "a") as outfile:
            for somefile in Path(appFolder).rglob("*"):
                if somefile.is_file():
                    print(
                        f"{self.color.OKCYAN}[+] Searching For hardcoded strings in File:{self.color.ENDC} \n{somefile}"
                    )
                    command = f"rabin2 -zzzqq  {somefile}"
                    regex_patterns = [
                        self.configs.BEARER_REGEX,
                        self.configs.HARDCODED_REGEX_2,
                        self.configs.HARDCODED_REGEX,
                    ]
                    for pattern in regex_patterns:
                        escaped_pattern = re.escape(pattern)
                        grep_command = f"{command} | grep -Pi {escaped_pattern}"
                        result = self.commands.run_os_commands(grep_command)

                        # Check if theres data to write

                        if result.returncode == 0 and result.stdout != "":
                            # Sort and remove duplicates, then write to temp_file
                            unique_lines = sorted(set(result.stdout.splitlines()))
                            joined_string = "\n".join(unique_lines) + "\n"
                            formated_string = self.format_content(joined_string)
                            print(
                                f"{self.color.OKGREEN}Writing Potential Hardcoded string to temporary file {self.color.ENDC}\n",
                                flush=True,
                            )
                            outfile.write(formated_string)

    def get_base64_strings(self, folder, base_name, platform):
        path_2_folder = Path(folder)
        output = f"{base_name}_{platform}_base64.txt"

        # TODO: refactor code:
        # avoid saving to file
        # use class memory

        if not self.temp_data:
            self.create_temp_file(path_2_folder)

        if not self.temp_base64_data:
            print("Processing base64 strings ...\n")
            base64_strings = re.findall(self.configs.BASE64_REGEX, self.temp_data)
            self.temp_base64_data = sorted(set(base64_strings))
            print("Base64 strings processed and stored in memory.")

        self.decode_base64(output)

    def create_temp_file(self, folder_path):
        print(f"Creating in-memory temp data from folder: {folder_path}")
        temp_data_list = []
        folder = Path(self.folder_name)
        

        for file in folder.rglob("*"):
            if file.is_file():
                command = f"rabin2 -zzzqq  {file}"
                try:
                    result = self.commands.run_os_commands(command)
                    # Sort and remove duplicates, then write to temp_file
                    unique_lines = sorted(set(result.stdout.splitlines()))

                    if result.stdout.strip():
                        joined_string = "\n".join(unique_lines) + "\n"
                        print(
                            f"{self.color.OKCYAN}[+] Getting strings from:{self.color.ENDC} \n{file}\n"
                        )
                        temp_data_list.append(joined_string)
                except Exception as error:
                    print(
                        f"{self.color.FAIL}[!] Error processing file {self.color.ENDC}{file} : {error}"
                    )
        self.temp_data = "".join(temp_data_list)

    def decode_base64(self, output):
        """Decode base64 strings stored in memory and write to file"""
        print("Decoding base64 strings ==> \n")
        with open(output, "a") as out_f:
            for string in self.temp_base64_data:
                string = string.strip()
                if string:  # Check if string is not empty
                    try:
                        command = f"echo '{string}' | base64 -d | grep -PI '[\\s\\S]+'"
                        decoded = self.commands.run_os_commands(command)

                        if decoded.stdout:
                            print(
                                f"{self.color.OKCYAN}Encoded String: {string}{self.color.ENDC}\nDecoded String: {decoded.stdout}\n",
                                flush=True,
                            )
                            out_f.write(
                                f"Encoded String: {string}\nDecoded string: {decoded.stdout}\n"
                            )
                    except Exception as e:
                        print(
                            f"{self.color.FAIL}[!] Error decoding base64 string {string}: {e}{self.color.ENDC}"
                        )

    def get_deeplinks(self, application_folder, basename):
        url_name = f"{basename}_URLs.txt"
        ip_name = f"{basename}_IPs.txt"

        for file in Path(application_folder).rglob("*"):
            if file.is_file():
                self.file_count += 1  # Track how many files are scanned
                command = f"rabin2 -zzzqq {file}"
                try:
                    result = self.commands.run_os_commands(command)
                    unfiltered_urls = re.findall(self.configs.URL_REGEX, result.stdout)
                    filtered_urls = [
                        url
                        for url in unfiltered_urls
                        if not re.search(self.configs.DEEPLINKS_IGNORE_REGEX, url)
                    ]
                    if filtered_urls:
                        filtered_urls = sorted(set(filtered_urls))
                        self.all_urls.extend([url for url in filtered_urls])

                    ips = re.findall(self.configs.IP_REGEX, result.stdout)

                    if len(ips) != 0:
                        print(
                            f"{self.color.WARNING}[+] Possible IP(s) found: {self.color.ENDC}",
                            ips,
                            flush=True,
                        )
                        self.all_ips.extend([ip for ip in ips])

                except Exception as e:
                    print(
                        f"{self.color.FAIL}[!] Error extracting Links {e}{self.color.ENDC}"
                    )
        # Remove all duplicates and save to file
        self.sort_urls_and_ips(url_name, self.all_urls, urls=True)
        self.sort_urls_and_ips(ip_name, self.all_ips)

    def sort_urls_and_ips(self, filename, data, **kwargs):
        with open(filename, "w") as f:
            unique_lines = sorted(set(data))
            for line in unique_lines:
                if "urls" in kwargs:
                    self.url_count += 1
                    print(
                        f"{self.color.OKCYAN}[+] Found {self.url_count} unique URL(s) from {self.file_count} application files: {self.color.ENDC}"
                    )
                f.write(f"{line}\n")

    def format_content(self, content):

        # Replace escaped newline and tab characters
        content = re.sub(r"\\n", "\n", content)
        content = re.sub(r"\\t", "\t", content)
        return content

    def mobile_scripts(
        self,
        decompiled_folder,
        hardcoded_filename,
        platform,
        basename,
        output_dir,
        base64_name,
    ):
        if platform == "ipa":
            self.ios_specific_scan(decompiled_folder, basename, output_dir)
        ## Run scripts that are common to both iOS and Android

        self.find_hardcoded_data(decompiled_folder, hardcoded_filename)
        self.get_base64_strings(output_dir, base64_name, platform)
        self.get_deeplinks(decompiled_folder, basename)
        self.scan_with_nuclei(decompiled_folder, output_dir, platform)

    def ios_specific_scan(self, decompiled_app_folder, file_basename, output_dir):
        # iOS specific script
        # property dump
        self.ios_prop_dump(decompiled_app_folder, output_dir)
        # get url scheme
        self.ios_URL_scheme(decompiled_app_folder, basename=file_basename)
        # find files
        self.find_files(appFolder=decompiled_app_folder)

    def ios_URL_scheme(self, decomplied_folder, basename):
        filename = f"{basename}_iOS_URL_schemes.txt"
        plist_file = self.validator.find_specific_file("Info.plist", decomplied_folder)

        command = f"xmlstarlet sel -t -v 'plist/dict/array/dict[key = \"CFBundleURLSchemes\"]/array/string' -nl {plist_file}"
        results = self.commands.run_os_commands(command)

        with open(filename, "w") as output_file:
            url_schemes = sorted(set(results.stdout.splitlines))
            for scheme in url_schemes:
                output_file.write(f"{scheme}\n")

    def ios_prop_dump(self, decompiled_folder, output_dir):
        print("dumping ios files")
        db_command = (
            f"property-lister -db {decompiled_folder} -o {output_dir}/results_db"
        )
        pl_command = (
            f"property-lister -pl {decompiled_folder} -o {output_dir}/results_pl"
        )
        self.commands.run_os_commands(db_command)
        self.commands.run_os_commands(pl_command)

    def inspect_application_files(self, application: str):
        platform = ""

        folder_name = self.decompile_application(application)
        output_name = f"{self.output_dir}/{self.file_name}"

        if self.file_type.lower() == "apk":
            platform = "android"
        else:
            platform = "ios"
        basename = f"{output_name}_{platform}"
        hardcoded = f"{basename}_hardcoded.txt"

        self.mobile_scripts(
            decompiled_folder=folder_name,
            hardcoded_filename=hardcoded,
            platform=platform,
            basename=basename,
            output_dir=self.output_dir,
            base64_name=output_name,
        )

        print(
            f"[+] Application scanning complete, your all files are located here:\n{self.color.OKGREEN}{self.output_dir}{self.color.ENDC}"
        )

    def install_nuclei_template(
        self, install_path="./output_directory/mobile/mobile-nuclei-templates"
    ):
        template_dir = Path(f"{install_path}")
        absolute_path = str(template_dir.resolve())

        # os.environ["GOBIN"] = absolute_path
        if not self.validator.check_folder_exists(absolute_path):
            print(
                f"Templates folder not present, Cloning templates into {absolute_path}"
            )
            github_repo = "https://github.com/optiv/mobile-nuclei-templates.git"
            command = f"git clone {github_repo} {absolute_path}"

            try:

                self.commands.run_os_commands(command)
                print("[+] Nuclei template Installed successfully")

            except Exception as e:
                print(f"Error during Installation {e}")
                return False

        return True

    def scan_with_nuclei(self, application_folder, output_dir, platform):

        nuclei_dir = "./output_directory/mobile/mobile-nuclei-templates"
        out_file = f"{output_dir}/{self.file_name}_nuclei_keys_results.txt"
        android_output = f"{output_dir}/{self.file_name}_nuclei_android_results.txt"

        # Check if template exists and install
        if not self.install_nuclei_template(nuclei_dir):
            return

        nuclei_command = (
            f"echo {application_folder} | nuclei -t {nuclei_dir}/Keys -o {out_file}"
        )
        android_nuclei = f"echo {application_folder} | nuclei -t {nuclei_dir}/{platform} -o {android_output}"
        try:
            print(f"Running command: {nuclei_command}")
            self.commands.run_os_commands(nuclei_command)
            if platform == "apk":
                self.commands.run_os_commands(android_nuclei)

        except Exception as e:
            print(f"Error running command: {e}")
