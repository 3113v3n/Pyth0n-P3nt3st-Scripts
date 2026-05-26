from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path


class MobileExtractionMixin:
    """Package extraction and output-folder setup helpers."""
    EXTRACTION_READY_MARKER = ".extraction_ready"

    def _get_folder_name(self, platform: str, package: str) -> str:
        self.templates_folder = f"{self.working_dir}/.tmp/mobile-nuclei-templates"
        platform_name = platform.title() if platform.lower() == "android" else platform
        base_dir = self.output_directory

        filename_without_ext = self.get_filename_without_extension(package)
        self.file_name = self.remove_spaces(filename_without_ext)
        self._cleanup_legacy_extraction_folders(base_dir, platform_name)

        self.create_folder(platform_name, search_path=base_dir)
        self.mobile_output_dir = f"{base_dir}/{platform_name}"
        return self._build_runtime_extraction_dir(package)

    @staticmethod
    def _package_fingerprint(package: str) -> str:
        target = Path(package).resolve()
        stat = target.stat()
        digest = hashlib.sha256()
        digest.update(str(target).encode("utf-8", errors="ignore"))
        digest.update(str(stat.st_size).encode("utf-8"))
        digest.update(str(stat.st_mtime_ns).encode("utf-8"))
        return digest.hexdigest()[:12]

    def _prune_duplicate_extraction_dirs(self, runtime_root: Path, keep: Path) -> None:
        """Remove same-app extraction duplicates while preserving the selected cache folder."""
        keep_path = keep.resolve()
        for candidate in runtime_root.glob(f"{self.file_name}_*"):
            if not candidate.is_dir():
                continue
            try:
                if candidate.resolve() == keep_path:
                    continue
            except OSError:
                continue
            shutil.rmtree(candidate, ignore_errors=True)

    def _build_runtime_extraction_dir(self, package: str) -> str:
        runtime_root = Path(self.working_dir) / ".tmp" / "mobile-extraction"
        runtime_root.mkdir(parents=True, exist_ok=True)

        fingerprint = self._package_fingerprint(package)
        deterministic = runtime_root / f"{self.file_name}_{fingerprint}"
        if deterministic.exists():
            self._prune_duplicate_extraction_dirs(runtime_root, deterministic)
            return str(deterministic)

        # Fallback compatibility for legacy timestamped extraction folders.
        legacy_candidates = sorted(runtime_root.glob(f"{self.file_name}_*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for candidate in legacy_candidates:
            if not candidate.is_dir():
                continue
            marker = candidate / self.EXTRACTION_READY_MARKER
            if marker.exists():
                target = candidate
                try:
                    candidate.rename(deterministic)
                    target = deterministic
                except OSError:
                    target = candidate
                self._prune_duplicate_extraction_dirs(runtime_root, target)
                return str(target)

        return str(deterministic)

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

        extraction_dir = Path(self.folder_name)
        marker = extraction_dir / self.EXTRACTION_READY_MARKER
        if extraction_dir.exists() and marker.exists():
            self.print_info_message(
                "Using cached extracted app folder",
                file_path=str(extraction_dir),
            )
            return self.folder_name, "cached"

        # Remove partial leftovers before extraction to avoid stale duplicates.
        if extraction_dir.exists():
            shutil.rmtree(extraction_dir, ignore_errors=True)
        extraction_dir.mkdir(parents=True, exist_ok=True)

        method = self._unzip_package(package, self.folder_name)
        try:
            marker.write_text("ok", encoding="utf-8")
        except OSError:
            pass
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
