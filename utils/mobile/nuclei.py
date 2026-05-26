from __future__ import annotations

import os
import re
import shutil
import tempfile
import textwrap
import time
from pathlib import Path


class MobileNucleiMixin:
    """Optional nuclei template management and execution."""
    INLINE_NAME_COL = 44
    INLINE_WRAP_WIDTH = 108

    @staticmethod
    def _condense_result_path(path_value: str) -> str:
        normalized = str(path_value or "").strip().replace("\\", "/")
        cwd = os.getcwd().replace("\\", "/").rstrip("/")
        if cwd and normalized.startswith(f"{cwd}/"):
            return normalized[len(cwd) + 1:]
        return normalized

    @staticmethod
    def _split_mobile_extraction_path(path_value: str) -> tuple[str, str]:
        match = re.match(r"^(?P<root>\.?tmp/mobile-extraction/[^/]+/)(?P<tail>.+)$", path_value)
        if not match:
            return "", path_value
        return match.group("root"), match.group("tail")

    @classmethod
    def _format_nuclei_result_line(cls, line: str) -> str:
        value = str(line or "").strip()
        if not value:
            return ""

        line_match = re.match(
            r"^\[(?P<name>[^\]]+)\]\s+\[(?P<source>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<rest>.+)$",
            value,
        )
        if not line_match:
            return value

        name = str(line_match.group("name")).strip()
        source = str(line_match.group("source")).strip() or "file"
        severity = str(line_match.group("severity")).strip() or "info"
        remainder = str(line_match.group("rest")).strip()

        secret_suffix = ""
        if remainder.endswith("]"):
            split_at = remainder.rfind(" [")
            if split_at > 0:
                candidate = remainder[split_at + 1:].strip()
                if candidate.startswith("[") and candidate.endswith("]"):
                    secret_suffix = candidate
                    remainder = remainder[:split_at].strip()

        condensed_path = cls._condense_result_path(remainder)
        root_path, tail_path = cls._split_mobile_extraction_path(condensed_path)
        first_path_segment = root_path if root_path else condensed_path
        prefix = f"[{name}]".ljust(cls.INLINE_NAME_COL) + f"[{source}] [{severity}] "
        first_line = f"{prefix}{first_path_segment}".rstrip()
        if secret_suffix:
            first_line = f"{first_line} {secret_suffix}"

        if not tail_path or tail_path == condensed_path:
            return first_line

        hanging_indent = " " * len(prefix)
        wrapped_tail = textwrap.wrap(
            tail_path,
            width=cls.INLINE_WRAP_WIDTH,
            initial_indent=hanging_indent,
            subsequent_indent=hanging_indent,
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not wrapped_tail:
            return first_line
        return "\n".join([first_line, *wrapped_tail])

    def _dedupe_output_file(self, path: Path) -> int:
        if not path.exists():
            return 0
        lines = []
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                value = line.strip()
                if value:
                    lines.append(value)
        if not lines:
            path.unlink(missing_ok=True)
            return 0

        unique_lines = list(dict.fromkeys(lines))
        with path.open("w", encoding="utf-8") as fh:
            for line in unique_lines:
                formatted = self._format_nuclei_result_line(line)
                if formatted:
                    fh.write(f"{formatted}\n")
        return len(unique_lines)

    @classmethod
    def _is_nuclei_template_sync_fresh(cls, template_dir: Path) -> bool:
        marker = template_dir / ".last_sync_epoch"
        if not marker.exists():
            return False
        if not (template_dir / "Keys").exists():
            return False
        try:
            last_sync = int(marker.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return False
        return (int(time.time()) - last_sync) < cls.NUCLEI_TEMPLATE_SYNC_TTL_SECONDS

    @staticmethod
    def _mark_nuclei_template_sync(template_dir: Path) -> None:
        marker = template_dir / ".last_sync_epoch"
        try:
            marker.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            pass

    def install_nuclei_template(self, install_path: str) -> bool:
        """Ensure mobile nuclei templates exist locally and are updated."""
        template_dir = Path(install_path).resolve()
        repository = "https://github.com/optiv/mobile-nuclei-templates.git"

        if self._nuclei_templates_synced and template_dir.exists():
            return True

        if not shutil.which("git"):
            self.print_error_message("git is required to update nuclei templates")
            return False

        if template_dir.exists():
            if (template_dir / ".git").exists():
                if self._is_nuclei_template_sync_fresh(template_dir):
                    self.print_info_message(
                        "Using cached mobile nuclei templates (recent sync found)",
                        file_path=str(template_dir),
                    )
                    self._nuclei_templates_synced = True
                    return True
                self.print_info_message(
                    "Updating mobile nuclei templates to latest version",
                    file_path=str(template_dir),
                )
                fetch = self.execute_command(["git", "-C", str(template_dir), "fetch", "--all", "--prune"])
                pull = self.execute_command(["git", "-C", str(template_dir), "pull", "--ff-only"])
                if fetch.returncode != 0 or pull.returncode != 0:
                    error = pull.stderr.strip() or fetch.stderr.strip() or "Unknown git error"
                    self.print_warning_message(
                        "Failed to update nuclei templates; continuing with local copy.",
                        file_path=error,
                    )
                    self._mark_nuclei_template_sync(template_dir)
                    self._nuclei_templates_synced = True
                    return True
                self._mark_nuclei_template_sync(template_dir)
                self._nuclei_templates_synced = True
                return True

            self.print_warning_message(
                "Existing nuclei template directory is not a git repository; recreating.",
                file_path=str(template_dir),
            )
            try:
                shutil.rmtree(template_dir)
            except OSError as error:
                self.print_error_message("Failed to recreate nuclei template directory", exception_error=error)
                return False

        try:
            template_dir.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            self.print_error_message("Failed to prepare nuclei template path", exception_error=error)
            return False

        self.print_info_message(
            "Cloning latest mobile nuclei templates",
            file_path=str(template_dir),
        )
        clone = self.execute_command(["git", "clone", "--depth", "1", repository, str(template_dir)])
        if clone.returncode != 0:
            self.print_error_message("Failed to clone nuclei templates", exception_error=clone.stderr.strip())
            return False

        self._mark_nuclei_template_sync(template_dir)
        self._nuclei_templates_synced = True
        return True

    def scan_with_nuclei(
        self,
        application_folder: str,
        output_dir: str,
        platform: str,
        use_cached_results: bool = False,
    ) -> dict:
        results = {"keys_results": 0, "platform_results": 0, "ran": False, "cached": False}

        if not shutil.which("nuclei"):
            return results

        nuclei_dir = self.templates_folder
        if not self.install_nuclei_template(nuclei_dir):
            return results

        out_file = Path(output_dir) / f"{self.file_name}_nuclei_keys_results.txt"
        platform_file = Path(output_dir) / f"{self.file_name}_nuclei_{platform}_results.txt"

        if use_cached_results:
            marker_epoch = 0
            marker_path = Path(nuclei_dir) / ".last_sync_epoch"
            if marker_path.exists():
                try:
                    marker_epoch = int(marker_path.read_text(encoding="utf-8").strip())
                except (OSError, ValueError):
                    marker_epoch = 0

            def is_fresh(path: Path) -> bool:
                if not path.exists():
                    return False
                if marker_epoch <= 0:
                    return True
                try:
                    return int(path.stat().st_mtime) >= marker_epoch
                except OSError:
                    return False

            cached_key = is_fresh(out_file)
            cached_platform = is_fresh(platform_file) if platform == "android" else False
            if cached_key or cached_platform:
                key_count = self._dedupe_output_file(out_file) if cached_key else 0
                platform_count = self._dedupe_output_file(platform_file) if cached_platform else 0
                results["keys_results"] = key_count
                results["platform_results"] = platform_count
                results["cached"] = True
                return results

        tmp_root = Path(self.working_dir) / ".tmp" / "nuclei"
        tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
            suffix=".txt",
            dir=str(tmp_root),
        ) as tmp:
            tmp.write(f"{application_folder}\n")
            input_file = tmp.name

        try:
            key_cmd = ["nuclei", "-silent", "-file", "-l", input_file, "-t", f"{nuclei_dir}/Keys", "-o", str(out_file)]
            key_res = self.execute_command(key_cmd)
            if key_res.returncode == 0:
                results["ran"] = True
            key_count = self._dedupe_output_file(out_file)
            if key_count > 0:
                results["keys_results"] = key_count

            if platform == "android":
                plat_cmd = [
                    "nuclei",
                    "-silent",
                    "-file",
                    "-l",
                    input_file,
                    "-t",
                    f"{nuclei_dir}/Android",
                    "-o",
                    str(platform_file),
                ]
                plat_res = self.execute_command(plat_cmd)
                if plat_res.returncode == 0:
                    results["ran"] = True
                platform_count = self._dedupe_output_file(platform_file)
                if platform_count > 0:
                    results["platform_results"] = platform_count
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

        return results
