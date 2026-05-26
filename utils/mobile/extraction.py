from __future__ import annotations

import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path


class MobileExtractionMixin:
    """Package extraction and output-folder setup helpers."""

    def _get_folder_name(self, platform: str, package: str) -> str:
        self.templates_folder = f"{self.working_dir}/.tmp/mobile-nuclei-templates"
        platform_name = platform.title() if platform.lower() == "android" else platform
        base_dir = self.output_directory

        filename_without_ext = self.get_filename_without_extension(package)
        self.file_name = self.remove_spaces(filename_without_ext)
        self._cleanup_legacy_extraction_folders(base_dir, platform_name)

        self.create_folder(platform_name, search_path=base_dir)
        self.mobile_output_dir = f"{base_dir}/{platform_name}"
        return self._build_runtime_extraction_dir()

    def _build_runtime_extraction_dir(self) -> str:
        runtime_root = Path(self.working_dir) / ".tmp" / "mobile-extraction"
        runtime_root.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        folder = tempfile.mkdtemp(prefix=f"{self.file_name}_{timestamp}_", dir=str(runtime_root))
        return str(Path(folder))

    @staticmethod
    def _cleanup_legacy_extraction_folders(base_dir: str, platform_name: str) -> None:
        """Delete non-output extraction folders left by older scanner versions."""
        platform_dir = Path(base_dir) / platform_name
        if not platform_dir.exists() or not platform_dir.is_dir():
            return

        for child in platform_dir.iterdir():
            if not child.is_dir():
                continue
            if child.name.endswith("_scan_results"):
                continue
            shutil.rmtree(child, ignore_errors=True)

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
        self.create_folder(folder_name=new_folder_name, search_path=self.mobile_output_dir)
        self.mobile_output_dir = f"{self.mobile_output_dir}/{new_folder_name}"

    def cleanup_extraction_folder(self, folder_name: str) -> None:
        """Retain decompiled/extracted directories for manual review."""
        if not folder_name:
            return
        try:
            safe_folder = self._validate_file_path(folder_name)
        except ValueError:
            return
        folder = Path(safe_folder)
        if folder.exists() and folder.is_dir() and getattr(self, "debug", False):
            self.print_info_message(
                f"Retaining decompiled app folder for manual review: {folder}"
            )

    def cleanup_nuclei_templates(self) -> None:
        """Remove mobile nuclei template clone (runtime cache) after assessment."""
        template_dir = str(getattr(self, "templates_folder", "")).strip()
        if not template_dir:
            return
        try:
            safe_template = self._validate_file_path(template_dir)
        except ValueError:
            return
        folder = Path(safe_template)
        if folder.exists() and folder.is_dir():
            shutil.rmtree(folder, ignore_errors=True)
