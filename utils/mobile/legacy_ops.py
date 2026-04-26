from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


class MobileLegacyOpsMixin:
    """Backward-compatible helper operations for mobile workflows."""

    @staticmethod
    def _validate_file_path(path: str) -> str:
        if "\x00" in path:
            raise ValueError(f"Null byte detected in path: {path!r}")
        if ".." in Path(path).parts:
            raise ValueError(f"Path traversal detected in path: {path!r}")
        return path

    @staticmethod
    def rename_folders_with_spaces(path: str) -> None:
        for root, dirs, _ in os.walk(path):
            for dir_name in dirs:
                if " " in dir_name:
                    old_path = os.path.join(root, dir_name)
                    new_path = os.path.join(root, dir_name.replace(" ", "_"))
                    os.rename(old_path, new_path)

    def update_grep_cmd(self) -> None:
        self.grep_cmd = "ggrep"

    @staticmethod
    def format_content(content: str) -> str:
        content = re.sub(r"\\n", "\n", content)
        content = re.sub(r"\\t", "\t", content)
        content = re.sub(r"\\r", "\r", content)
        return content

    def push_certs(self, certificate: str) -> None:
        safe_cert = self._validate_file_path(certificate)
        self.execute_command(["adb", "push", safe_cert, "/storage/emulated/0/"])

    def pull_package_with_keyword(self, keyword: str) -> None:
        """Best-effort ADB APK pull without shell pipelines."""
        if not shutil.which("adb"):
            self.print_error_message("adb not found on PATH")
            return

        packages_out = self.get_process_output(["adb", "shell", "pm", "list", "packages"])
        pkg = ""
        for line in packages_out.splitlines():
            line = line.strip()
            if keyword.lower() in line.lower() and line.startswith("package:"):
                pkg = line.split(":", 1)[1].strip()
                break

        if not pkg:
            self.print_error_message("Package not found")
            return

        paths_out = self.get_process_output(["adb", "shell", "pm", "path", pkg])
        apk_path = ""
        for line in paths_out.splitlines():
            line = line.strip()
            if line.startswith("package:") and "base.apk" in line:
                apk_path = line.split(":", 1)[1].strip()
                break

        if not apk_path:
            self.print_error_message("APK path not found.")
            return

        result = self.execute_command(["adb", "pull", apk_path, "./"])
        if result.returncode == 0:
            self.print_success_message(f"Successfully pulled {apk_path}")
        else:
            self.print_error_message("Failed to pull APK", exception_error=result.stderr.strip())
