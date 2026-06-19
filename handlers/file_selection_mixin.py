"""Reusable file-discovery and selection workflows for CLI handlers."""

from __future__ import annotations

import os
from typing import Any

from handlers.navigation import BackToPreviousMenu, sanitize_dialog_input
from handlers.opentui_menu import build_menu_options, ensure_opentui_menu_enabled, run_opentui_menu


class FileSelectionMixin:
    """Mixin that encapsulates file listing/filtering and selection prompts."""

    def create_folder(self, folder_name, search_path="./output_directory"):
        self.output_directory = f"{search_path}/{folder_name}"

        if not self.check_subdirectory_exists(folder_name, search_path=search_path):
            folder_path = self.output_directory
            os.makedirs(folder_path)

    def find_files(self, search_path):
        """Search for files in the given directory and all subdirectories."""
        for root, _, files in os.walk(search_path):
            for file in files:
                file_object = {
                    "filename": file,
                    "full_path": os.path.join(root, file),
                }
                self.files.append(file_object)
        return self.files

    def display_saved_files(self, dir_to_search, **kwargs):
        """Display to the user a list of files available."""
        # Always reset discovered files for this selection request.
        self.files = []
        self.find_files(dir_to_search)
        self.files = self._get_filtered_files(**kwargs)

        if not self.files:
            return None

        if len(self.files) == 1:
            return self._auto_select_single_file(**kwargs)

        return self._handle_analysis(**kwargs)

    def _get_filtered_files(self, **kwargs) -> list:
        """Get filtered files based on selection mode flags."""
        file_collection = self._get_file_collections()

        if kwargs.get("scan_extension"):
            return self._filter_files_by_extension(
                file_collection,
                kwargs["scan_extension"],
            )
        if kwargs.get("resume_scan"):
            return self._filter_unresponsive_host_files(file_collection["csv"])
        if kwargs.get("display_applications"):
            return file_collection["applications"]
        return self.files

    def _get_file_collections(self) -> dict:
        """Return useful file collections grouped by extension/type."""

        def get_files_by_type(ext):
            return [
                file
                for file in self.files
                if self.check_filetype(file["filename"], ext)
            ]

        csv_files = get_files_by_type("csv")
        xlsx_files = get_files_by_type("xlsx")
        both_files = csv_files + xlsx_files

        application_files = [
            file
            for file in self.files
            if self.check_filetype(file["filename"], "apk")
            or self.check_filetype(file["filename"], "ipa")
        ]

        return {
            "csv": csv_files,
            "xlsx": xlsx_files,
            "both": both_files,
            "applications": application_files,
        }

    @staticmethod
    def _filter_unresponsive_host_files(csv_files) -> list[Any] | None:
        """Filter to CSV files that contain unresponsive-host scan data."""
        unresponsive_file = [
            file
            for file in csv_files
            if "unresponsive_host" in file["filename"]
        ]
        if not unresponsive_file:
            return None
        return unresponsive_file

    def _filter_files_by_extension(self, collections, extension) -> Any | None:
        """Filter files by extension key (csv/xlsx/xlx/both)."""
        if extension not in ["csv", "xlsx", "xlx", "both"]:
            self.print_error_message(f"Invalid extension: {extension}")
            return None

        normalized_extension = "xlsx" if extension == "xlx" else extension
        filtered_files = collections[normalized_extension]
        if not filtered_files:
            self.print_error_message("No files found")
            return None
        return filtered_files

    def _display_file_options(self):
        """Backward-compatible no-op: selection details are rendered in OpenTUI."""
        return list(self.files)

    def _handle_analysis(self, **kwargs):
        """Route selection flow to the correct analysis action."""
        if kwargs.get("scan_extension"):
            return self.select_and_analyze_file("files")
        if kwargs.get("display_applications"):
            return self.select_and_analyze_file("applications")
        if kwargs.get("resume_scan"):
            return self.select_and_analyze_file()
        return None

    def _auto_select_single_file(self, **kwargs):
        """Auto-select a single discovered file and avoid redundant prompts."""
        if not self.files:
            self.print_error_message("No files found to auto-select.")
            return None

        selected = self.files[0]
        self.print_info_message(
            "Only one file found. Selecting it automatically.",
            file_path=selected["filename"],
        )

        try:
            if kwargs.get("scan_extension"):
                return self.files, 0
            if kwargs.get("display_applications"):
                return selected
            if kwargs.get("resume_scan"):
                self.filepath = selected["full_path"]
                starting_ip = self.get_last_unresponsive_ip(self.filepath)
                if not starting_ip:
                    self.print_error_message(
                        "Unable to resume scan: selected file does not contain any valid IPs."
                    )
                    return None
                return starting_ip
        except Exception as error:
            self.print_error_message(
                message="Failed to auto-select the discovered file",
                exception_error=error,
            )
            return None

        return None

    def index_out_of_range_display(self, input_str, data_list) -> int:
        """Prompt for a numeric selection and return its 0-based index."""
        if not data_list:
            raise ValueError("index_out_of_range_display requires at least one selectable item")
        ensure_opentui_menu_enabled(context="interactive file selection")
        tui_options = build_menu_options(
            list(data_list),
            label_getter=lambda item, _index: (
                item.get("filename", str(item)) if isinstance(item, dict) else str(item)
            ),
            value_getter=lambda _item, index: index,
            description_getter=lambda item, _index: (
                item.get("full_path", "") if isinstance(item, dict) else ""
            ),
            badge_getter=lambda _item, index: str(index + 1),
            meta_getter=lambda item, _index: (
                f"Path selector • {item.get('filename', '')}" if isinstance(item, dict) else ""
            ),
        )
        selected = run_opentui_menu(
            title="Select an item",
            prompt=sanitize_dialog_input(input_str),
            options=tui_options,
            footer="↑/↓ or j/k navigate • number keys jump • Enter selects • Esc goes back",
            subtitle="Review filenames and paths before choosing an artifact to analyze",
            cancel_raises=BackToPreviousMenu,
        )
        if selected is None:
            raise RuntimeError("OpenTUI file selection ended without a choice")
        return int(selected.value)

    def select_and_analyze_file(self, to_analyze: str = "") -> tuple | str | None:
        """Prompt user to choose an item and return the scan context."""
        if not self.files:
            self.print_error_message("No files available for selection.")
            return None

        if len(self.files) == 1:
            selected = self.files[0]
            self.print_info_message(
                "Only one file found. Selecting it automatically.",
                file_path=selected["filename"],
            )
            if to_analyze == "files":
                return self.files, 0
            if to_analyze == "applications":
                return selected

            try:
                self.filepath = selected["full_path"]
                starting_ip = self.get_last_unresponsive_ip(self.filepath)
                if not starting_ip:
                    self.print_error_message(
                        "Unable to resume scan: selected file does not contain any valid IPs."
                    )
                    return None
                return starting_ip
            except Exception as error:
                self.print_error_message(
                    message="Failed to prepare single-file analysis",
                    exception_error=error,
                )
                return None

        if to_analyze == "files":
            selected_file = self.index_out_of_range_display(
                "Please enter the file number you would like to scan first: ",
                self.files,
            )
            return self.files, selected_file

        if to_analyze == "applications":
            selected_app = self.index_out_of_range_display(
                "Select the application to scan: ",
                self.files,
            )
            return self.files[selected_app]

        selected_file = self.index_out_of_range_display(
            "Please enter the file number displayed above: ",
            self.files,
        )
        self.filepath = self.files[selected_file]["full_path"]
        starting_ip = self.get_last_unresponsive_ip(self.filepath)
        return starting_ip

    def do_analysis(self, to_analyze: str = "") -> tuple | str | None:
        """Backward-compatible alias for select_and_analyze_file()."""
        return self.select_and_analyze_file(to_analyze)
