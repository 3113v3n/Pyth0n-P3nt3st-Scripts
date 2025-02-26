from pathlib import Path
import os
import re
from handlers import FileHandler, ScreenHandler
from utils.shared import Commands, Config


class MobileCommands(FileHandler, Config, Commands, ScreenHandler):
    def __init__(self):
        super().__init__()

        self.mobile_output_dir = ""
        self.file_type = ""
        self.folder_name = ""
        self.file_name = ""
        self.file_count = 0
        self.temp_data = ""
        self.temp_base64_data = ""
        self.templates_folder = ""

    @staticmethod
    def rename_folders_with_spaces(path):
        for root, dirs, _ in os.walk(path):
            for dir_name in dirs:
                if " " in dir_name:  # Check if the folder name contains a space
                    new_name = dir_name.replace(
                        " ", "_"
                    )  # Replace spaces with underscores
                    old_path = os.path.join(root, dir_name)
                    new_path = os.path.join(root, new_name)
                    os.rename(old_path, new_path)  # Rename the folder
                    # print(f"Renamed: {old_path} -> {new_path}")

    @staticmethod
    def format_content(content):
        # Replace escaped newline and tab characters
        content = re.sub(r"\\n", "\n", content)
        content = re.sub(r"\\t", "\t", content)
        return content

    def push_certs(self, certificate):
        self.run_os_commands(f"adb push {certificate} /storage/emulated/0/")

    def pull_package_with_keyword(self, keyword):
        """Pull application apk
        Requirement: Ensure device is connected via USB
        """
        # TODO: Work in progress
        pkg_cmd = (
            f"adb shell pm list packages | grep '{keyword}'|head -n 1|cut -d ':' -f2"
        )
        pkg = self.get_process_output(pkg_cmd).strip()

        if pkg:
            # Get the APK path
            path_cmd = f"adb shell pm path {pkg} | cut -d ':' -f2 | grep 'base.apk'"
            apk_path = self.get_process_output(path_cmd).strip()

            if apk_path:
                # pull the APK
                pull_cmd = f"adb pull {apk_path} ./"
                self.run_os_commands(pull_cmd)
                self.print_success_message(f"Successfully pulled {apk_path}")
            else:
                self.print_error_message("APK path not found.")
        else:
            self.print_error_message("Package not found")

    # Decompile APk
    def _get_folder_name(self, platform, package):
        """Returns application folder name and removes spaces in case they exist
        :param:
            platform: Android / iOS
            Package: This is the package name

        :return:
            Folder name
        """
        self.templates_folder = self.output_directory + "/mobile-nuclei-templates"
        platform = platform.title() if platform == "android" else platform

        base_dir = self.output_directory

        # Handle platform-specific file

        filename_without_ext = self.get_filename_without_extension(package)
        self.file_name = self.remove_spaces(filename_without_ext)

        self.create_folder(platform, search_path=base_dir)
        self.mobile_output_dir = f"{base_dir}/{platform}"
        folder_name = self.remove_spaces(
            f"{self.mobile_output_dir}/{filename_without_ext}"
        )
        return folder_name

    def _unzip_package(self, package, folder_name):
        """Unzips application apk or ipa file using unzip and apktool

        :param:
            package: ==> application package
        """
        try:
            android_cmd = f"apktool d '{package}' -o {folder_name}"
            ios_cmd = f"unzip '{package}' -d {self.folder_name}"
            command = android_cmd if self.file_type.lower() == "apk" else ios_cmd
            if not self.check_folder_exists(folder_name):

                self.print_success_message(
                    f" Decompiling the {self.file_name} application ..."
                )
                result = self.run_os_commands(command)
                if result.returncode == 0:
                    self.print_success_message(" Decompiling Successful")
                else:
                    raise FileNotFoundError
        except Exception as e:
            self.print_error_message(" Error", exception_error=e)

    def decompile_application(self, package):
        """
        Takes an apk / ios file and decompiles them using
        apktool or unzip respectively

        """
        self.file_type = self.get_file_extension(package)  # ipa / apk

        # Get folder name from provided package name
        self.folder_name = (
            self._get_folder_name("android", package)
            if self.file_type == "apk"
            else self._get_folder_name("iOS", package)
        )
        self._unzip_package(package, self.folder_name)

        return self.folder_name

    def find_app_files(self, app_folder, output):
        with open(output, "a") as output_file:
            for file in Path(app_folder).rglob("*"):
                if file.is_file():
                    command = f'rabin2 -zzzqq "{file}" 2>/dev/null | grep -Pi {self.IOS_FILE_SEARCH} | sort -uf'
                    result = self.run_os_commands(command)
                    if result.stdour.strip():
                        output_file.write(f"{result.stdout}")

    def find_hardcoded_data(self, app_folder, output):
        with open(output, "a") as outfile:
            for file in Path(app_folder).rglob("*"):
                if file.is_file():
                    self.print_info_message(
                        "Searching For hardcoded strings in File", file=file
                    )
                    command = f"rabin2 -zzzqq  {file}"
                    regex_patterns = [
                        self.BEARER_REGEX,
                        self.HARDCODED_REGEX_2,
                        self.HARDCODED_REGEX,
                    ]
                    for pattern in regex_patterns:
                        escaped_pattern = re.escape(pattern)
                        grep_command = f"{command} | grep -Pi {escaped_pattern}"
                        result = self.run_os_commands(grep_command)

                        # Check if there's data to write

                        if result.returncode == 0 and result.stdout != "":
                            # Sort and remove duplicates, then write to temp_file
                            unique_lines = sorted(set(result.stdout.splitlines()))
                            joined_string = "\n".join(unique_lines) + "\n"
                            formated_string = self.format_content(joined_string)
                            self.print_success_message(
                                "Writing Potential Hardcoded string to temporary file ",
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
            self.print_info_message("Processing base64 strings ...")
            base64_strings = re.findall(self.BASE64_REGEX, self.temp_data)
            self.temp_base64_data = sorted(set(base64_strings))
            self.print_success_message("Base64 strings processed and stored in memory.")

        self.decode_base64(output)

    def create_temp_file(self, folder_path):
        self.print_info_message(
            "Creating in-memory temp data from folder: ", file=folder_path
        )
        temp_data_list = []
        folder = Path(self.folder_name)

        for file in folder.rglob("*"):
            if file.is_file():
                command = f"rabin2 -zzzqq  {file}"
                try:
                    result = self.run_os_commands(command)
                    # Sort and remove duplicates, then write to temp_file
                    unique_lines = sorted(set(result.stdout.splitlines()))

                    if result.stdout.strip():
                        joined_string = "\n".join(unique_lines) + "\n"
                        self.print_info_message(" Getting strings from: ", file=file)
                        temp_data_list.append(joined_string)
                except Exception as error:
                    self.print_error_message(
                        message="Error processing file ", exception_error=error
                    )

        self.temp_data = "".join(temp_data_list)

    def decode_base64(self, output):
        """Decode base64 strings stored in memory and write to file"""
        loader = self.show_loader(
            "Decoding base64 strings ", "Decoding Complete", continuous=True
        )
        try:
            with open(output, "a") as out_f:
                # Set loading variable
                for string in self.temp_base64_data:
                    string = string.strip()
                    if string:  # Check if string is not empty
                        try:
                            command = (
                                f"echo '{string}' | base64 -d | grep -PI '[\\s\\S]+'"
                            )
                            decoded = self.run_os_commands(command)

                            if decoded.stdout:
                                self.print_info_message(
                                    message="Encoded String: ",
                                    flush=True,
                                    encoded_string=string,
                                )
                                self.print_success_message(
                                    message="Decoded String: ",
                                    extras=decoded.stdout,
                                    flush=True,
                                )
                                out_f.write(
                                    f"Encoded String: {string}\nDecoded string: {decoded.stdout}\n"
                                )
                        except Exception as e:
                            self.print_error_message(
                                message=f"Error decoding base64 string {string}",
                                exception_error=e,
                            )
        except Exception as e:
            self.print_error_message(
                message="Error decoding base64 strings", exception_error=e
            )
        finally:
            loader.stop()

    def get_deeplinks(self, application_folder, basename):
        url_name = f"{basename}_URLs.txt"
        ip_name = f"{basename}_IPs.txt"

        file_count = 0
        all_ips = []
        all_urls = []

        for file in Path(application_folder).rglob("*"):
            if file.is_file():
                file_count += 1  # Track how many files are scanned
                command = f"rabin2 -zzzqq {file}"
                try:
                    result = self.run_os_commands(command)
                    unfiltered_urls = re.findall(self.URL_REGEX, result.stdout)

                    # returns a list of URLS that don't match the ignored REGEX
                    filtered_urls = list(
                        filter(
                            lambda url: not re.search(self.DEEPLINKS_IGNORE_REGEX, url),
                            unfiltered_urls,
                        )
                    )
                    if filtered_urls:
                        filtered_urls = sorted(set(filtered_urls))
                        all_urls.extend([url for url in filtered_urls])

                    ips = re.findall(self.IP_REGEX, result.stdout)

                    if len(ips) != 0:
                        self.print_warning_message(
                            message="Possible IP(s) found", data=ips, flush=True
                        )
                        all_ips.extend([ip for ip in ips])

                except Exception as e:
                    self.print_error_message(
                        message="Error extracting Links ", exception_error=e
                    )
        # Update instance variables
        self.file_count = file_count

        # Process IPs and URLs
        ip_count = self.sort_urls_and_ips(ip_name, all_ips) if all_ips else 0
        url_count = self.sort_urls_and_ips(url_name, all_urls) if all_urls else 0

        # Print success message
        if ip_count > 0:
            self.print_success_message(
                f" Found {ip_count} unique IP(s) from {file_count} application files: ",
            )
        if url_count > 0:
            self.print_success_message(
                f" Found {url_count} unique URL(s) from {file_count} application files: ",
            )

    @staticmethod
    def sort_urls_and_ips(filename, data):
        """Sort and save URLs or IPs to file

        Args:
            filename: Output file name
            data: List of URLs or IPs to process
        Returns:
            int: Count of unique items written
        """
        if not data:
            return

        unique_lines = sorted(set(data))
        count = len(unique_lines)  # Local counter
        with open(filename, "w") as f:
            for line in unique_lines:
                f.write(f"{line}\n")
        return count

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
        # Run scripts that are common to both iOS and Android

        self.find_hardcoded_data(decompiled_folder, hardcoded_filename)
        self.get_base64_strings(output_dir, base64_name, platform)
        self.get_deeplinks(decompiled_folder, basename)
        self.scan_with_nuclei(decompiled_folder, output_dir, platform)

    def ios_specific_scan(self, decompiled_app_folder, file_basename, output_dir):
        # iOS specific script
        # property dump
        self.ios_prop_dump(decompiled_app_folder, output_dir)
        # get url scheme
        self.ios_url_scheme(decompiled_app_folder, basename=file_basename)
        # find files
        self.find_app_files(app_folder=decompiled_app_folder, output=output_dir)

    def ios_url_scheme(self, decompiled_folder, basename):
        filename = f"{basename}_iOS_URL_schemes.txt"
        plist_file = self.find_specific_file("Info.plist", decompiled_folder)

        command = (
            f"xmlstarlet sel -t -v 'plist/dict/array/dict[key = \"CFBundleURLSchemes\"]/array/string' -nl "
            f"{plist_file}"
        )
        results = self.run_os_commands(command)

        with open(filename, "w") as output_file:
            url_schemes = sorted(set(results.stdout.splitlines))
            for scheme in url_schemes:
                output_file.write(f"{scheme}\n")

    def ios_prop_dump(self, decompiled_folder, output_dir):
        self.print_info_message("dumping ios files")
        db_command = (
            f"property-lister -db {decompiled_folder} -o {output_dir}/results_db"
        )
        pl_command = (
            f"property-lister -pl {decompiled_folder} -o {output_dir}/results_pl"
        )
        self.run_os_commands(db_command)
        self.run_os_commands(pl_command)

    def inspect_application_files(self, application: str, test_domain: str):
        try:
            self.update_output_directory(test_domain)
            folder_name = self.decompile_application(application)

            # To store our scan results
            self.create_subfolder()
            output_name = f"{self.mobile_output_dir}/{self.file_name}"

            # Rename folder/subfolders that contain spaces to avoid errors
            self.rename_folders_with_spaces(folder_name)

            platform = "android" if self.file_type.lower() == "apk" else "ios"
            basename = f"{output_name}_{platform}"
            hardcoded = f"{basename}_hardcoded.txt"

            self.mobile_scripts(
                decompiled_folder=folder_name,
                hardcoded_filename=hardcoded,
                platform=platform,
                basename=basename,
                output_dir=self.mobile_output_dir,
                base64_name=output_name,
            )

            self.print_success_message(
                message="Application scanning complete, all your files are located here :==>",
                mobile_success=self.mobile_output_dir,
            )
            self.flush_system()
        except Exception as e:
            self.print_error_message(
                message="Error during mobile assessment", exception_error=e
            )
        finally:
            # Clean up remaining processes
            self._cleanup_processes()

    def _cleanup_processes(self):
        """Clean up remaining processes"""
        try:
            # clean temp data
            self.temp_data = ""
            self.temp_base64_data = ""
            # Flush buffers
            self.flush_system("I/O")
            self.kill_processes()
        except Exception as e:
            self.print_error_message(message="Error during cleanup", exception_error=e)

    def create_subfolder(self):
        """Create subfolder from the filename of package being scanned to score scan results"""
        new_folder_name = f"{self.file_name}_scan_results"
        updated_output_directory = f"{self.folder_name}_scan_results"

        self.create_folder(
            folder_name=new_folder_name, search_path=self.mobile_output_dir
        )
        self.mobile_output_dir = updated_output_directory

    def install_nuclei_template(self, install_path):
        template_dir = Path(f"{install_path}")
        absolute_path = str(template_dir.resolve())

        # os.environ["GOBIN"] = absolute_path
        if not self.check_folder_exists(absolute_path):

            self.print_warning_message(
                message="Templates folder not present, Cloning templates into ",
                file_path=absolute_path,
            )
            github_repo = "https://github.com/optiv/mobile-nuclei-templates.git"
            command = f"git clone {github_repo} {absolute_path}"

            try:

                self.run_os_commands(command)
                self.print_success_message(" Nuclei template Installed successfully")

            except Exception as e:
                self.print_error_message(
                    message="Error during Installation ", exception_error=e
                )
                return False

        return True

    def scan_with_nuclei(self, application_folder, output_dir, platform):

        nuclei_dir = self.templates_folder
        out_file = f"{output_dir}/{self.file_name}_nuclei_keys_results.txt"
        android_output = f"{output_dir}/{self.file_name}_nuclei_android_results.txt"

        # Check if the template exists and install
        if not self.install_nuclei_template(nuclei_dir):
            return

        nuclei_command = (
            f"echo {application_folder} | nuclei -t {nuclei_dir}/Keys -o {out_file}"
        )

        try:

            self.run_os_commands(nuclei_command)
            if platform == "android":
                android_nuclei = (
                    f"echo {application_folder} | nuclei -t {nuclei_dir}/{platform.title()} -o "
                    f"{android_output}"
                )
                self.run_os_commands(android_nuclei)

        except Exception as e:
            self.print_error_message(message="Error running command", exception_error=e)
