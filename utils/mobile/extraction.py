from __future__ import annotations

import shutil
import zipfile


class MobileExtractionMixin:
    """Package extraction and output-folder setup helpers."""

    def _get_folder_name(self, platform: str, package: str) -> str:
        self.templates_folder = f"{self.output_directory}/mobile-nuclei-templates"
        platform_name = platform.title() if platform.lower() == "android" else platform
        base_dir = self.output_directory

        filename_without_ext = self.get_filename_without_extension(package)
        self.file_name = self.remove_spaces(filename_without_ext)

        self.create_folder(platform_name, search_path=base_dir)
        self.mobile_output_dir = f"{base_dir}/{platform_name}"
        return self.remove_spaces(f"{self.mobile_output_dir}/{filename_without_ext}")

    def _extract_with_apktool(self, package: str, folder_name: str) -> bool:
        if not shutil.which("apktool"):
            return False
        cmd = ["apktool", "d", "-f", package, "-o", folder_name]
        result = self.execute_command(cmd)
        if result.returncode != 0:
            if self.debug:
                self.print_warning_message("apktool decompile failed", file_path=result.stderr.strip())
            return False
        return True

    @staticmethod
    def _extract_archive(package: str, folder_name: str) -> None:
        with zipfile.ZipFile(package, "r") as archive:
            archive.extractall(folder_name)

    def _unzip_package(self, package: str, folder_name: str) -> str:
        """Extract APK/IPA package and return extraction method used."""
        safe_package = self._validate_file_path(package)
        safe_folder = self._validate_file_path(folder_name)

        if self.check_folder_exists(safe_folder):
            return "cached"

        self.print_info_message(f"Decompiling/extracting {self.file_name} application...")

        if self.file_type.lower() == "apk":
            if self._extract_with_apktool(safe_package, safe_folder):
                self.print_success_message("Decompiling successful with apktool")
                return "apktool"

        try:
            self._extract_archive(safe_package, safe_folder)
            self.print_success_message("Archive extraction successful")
            return "zip"
        except (zipfile.BadZipFile, OSError) as error:
            self.print_error_message("Failed to extract package", exception_error=error)
            raise

    def decompile_application(self, package: str) -> tuple[str, str]:
        self.file_type = self.get_file_extension(package).lower()
        if self.file_type not in {"apk", "ipa"}:
            raise ValueError(f"Unsupported mobile package type: {self.file_type}")

        platform = "android" if self.file_type == "apk" else "iOS"
        self.folder_name = self._get_folder_name(platform, package)
        method = self._unzip_package(package, self.folder_name)
        return self.folder_name, method

    def create_subfolder(self) -> None:
        new_folder_name = f"{self.file_name}_scan_results"
        updated_output_directory = f"{self.folder_name}_scan_results"
        self.create_folder(folder_name=new_folder_name, search_path=self.mobile_output_dir)
        self.mobile_output_dir = updated_output_directory
