"""
file_handler.py — File I/O, CSV/Excel operations, and file management utilities.

Security: _safe_path() validates that user-supplied filenames cannot escape the
output directory via path-traversal sequences such as "../../etc/passwd".

Performance: IP sorting now uses key=ipaddress.ip_address (function reference)
instead of an equivalent lambda, removing per-element object construction overhead.

Naming: do_analysis() → select_and_analyze_file(); flat_content → deduplicated_ips.
"""

import os
import errno
from typing import Any, TextIO
import pandas
from datetime import datetime
from pathlib import Path
import shutil
from handlers.file_selection_mixin import FileSelectionMixin
from handlers.messages import DisplayHandler
from utils.shared import Validator
from utils.shared.text_formatting import (
    beautify_structured_text,
    prepare_text_for_write,
)
import ipaddress


class FileHandler(FileSelectionMixin, Validator, DisplayHandler):
    """Handle file I/O, CSV/Excel operations, and output-directory management."""
    BYTES_PER_MB = 1024 * 1024
    DEFAULT_XLSX_MIN_FREE_MB = 256
    XLSX_HEADROOM_MULTIPLIER = 3.0
    FONT_NAME = "Calibri Light"
    FONT_SIZE = 12
    FONT_COLOR = "white"
    BG_COLOR = "black"
    EXCEL_SHEETNAME_MAX_LEN = 31
    _EXCEL_INVALID_SHEET_CHARS = set('[]:*?/\\')
    _EXCEL_FORMULA_PREFIXES = ("=", "+", "-", "@")

    def __init__(self) -> None:
        super().__init__()
        self.assessment_domain = ""  # one of [internals, external, mobile]
        self.working_dir = os.getcwd()
        self.output_directory = (
            # directory to save our output files
            f"{self.working_dir}/output_directory"
        )
        self.filepath = ""  # full path to a saved file
        self.files = []
        self.live_hosts_file = ""
        self.unresponsive_hosts_file = ""
        self.existing_unresponsive_ips = set()
        self._csv_cache: dict[str, set[str]] = {}
        self._csv_cache_loaded: set[str] = set()

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.working_dir = os.getcwd()
        self.output_directory = f"{self.working_dir}/output_directory"
        self.filepath = ""
        self.files = []
        self.live_hosts_file = ""
        self.unresponsive_hosts_file = ""
        self._csv_cache = {}
        self._csv_cache_loaded = set()

    @classmethod
    def reset_class_states(cls):
        """Deprecated — use reset_state() on the instance instead."""
        cls.working_dir = os.getcwd()
        cls.output_directory = f"{cls.working_dir}/output_directory"
        cls.filepath = ""
        cls.files = []
        cls.live_hosts_file = ""
        cls.unresponsive_hosts_file = ""

    # ------------------------------------------------------------------
    # Security: path traversal prevention
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_path(base_dir: str, filename: str) -> Path:
        """Resolve *filename* relative to *base_dir* and assert it stays inside.

        Prevents path-traversal attacks where a crafted filename such as
        "../../etc/passwd" would escape the intended output directory.

        Args:
            base_dir: Trusted root directory the file must live under.
            filename: Filename or relative path to resolve.

        Returns:
            Resolved absolute Path object.

        Raises:
            ValueError: If the resolved path is outside *base_dir*.
        """
        # [Security] Prevent path traversal.
        resolved_base = Path(base_dir).resolve()
        resolved_path = (resolved_base / filename).resolve()
        try:
            resolved_path.relative_to(resolved_base)
        except ValueError as error:
            raise ValueError(
                f"Path traversal detected: '{filename}' resolves outside '{base_dir}'"
            ) from error
        return resolved_path

    @staticmethod
    def _assert_not_symlink(path: Path) -> None:
        """Reject symlink targets before writing to avoid link-traversal clobbering."""
        try:
            if path.is_symlink():
                raise ValueError(f"Refusing to write via symlink path: {path}")
        except OSError as error:
            raise ValueError(f"Unable to validate output path safety: {path}") from error

    @classmethod
    def _open_secure_output_file(
        cls,
        path: Path,
        *,
        append: bool,
        encoding: str = "utf-8",
    ) -> TextIO:
        """Open output files with restrictive permissions and no symlink following."""
        path.parent.mkdir(parents=True, exist_ok=True)
        cls._assert_not_symlink(path)

        if hasattr(os, "O_NOFOLLOW"):
            flags = os.O_WRONLY | os.O_CREAT
            flags |= os.O_APPEND if append else os.O_TRUNC
            flags |= os.O_NOFOLLOW
            fd = os.open(path, flags, 0o600)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return os.fdopen(fd, "a" if append else "w", encoding=encoding)

        handle = path.open("a" if append else "w", encoding=encoding)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return handle

    def set_new_dir(self, new_path):
        """Universal function to update output directory"""
        base_dir = f"{self.output_directory}/{new_path}"

        # create the directory if its absent
        self.create_folder(new_path)
        return base_dir

    def update_output_directory(self, domain):
        """
        Depending on the test domain provided,
        we update the output directory for various file output
        """
        handlers = {
            "internal": lambda: self.set_new_dir("Internal"),
            "mobile": lambda: self.set_new_dir("Mobile"),
            "external": lambda: self.set_new_dir("External"),
            "password": lambda: self.set_new_dir("Password"),
            "va": lambda: self.set_new_dir("Vulnerability-Assessment")
        }
        dir_handler = handlers.get(domain)
        if dir_handler:
            return dir_handler()
        else:
            self.print_error_message(
                f"Can not create directory for invalid domain: {domain}"
            )

    def save_txt_file(self, filename, content):
        """
        Save content to txt file

        :param filename: Name of the file
        :param content: Content of the file
        """
        target_path = self._safe_path(self.output_directory, filename)
        self.filepath = str(target_path)
        prepared = self._prepare_text_for_write(
            content,
            beautify_structured=True,
            wrap_long_lines=False,
        )
        with self._open_secure_output_file(target_path, append=True) as file:
            file.write(prepared)
            if not prepared.endswith("\n"):
                file.write("\n")

    def write_to_multiple_sheets(
            self, dataframe_objects: list, filename: str
    ):
        """Dataframe Object containing dataframes and their equivalent sheet names"""
        report_name = self.generate_unique_name(filename, extension="xlsx")
        report_path = self._safe_path(self.output_directory, report_name)
        self._assert_not_symlink(report_path)
        self.filepath = str(report_path)
        excel_tmpdir = self._get_excel_tmpdir()
        self._warn_if_low_excel_space(dataframe_objects, excel_tmpdir)

        # Define formats
        header_formats = {
            "font_name": self.FONT_NAME,
            "font_size": self.FONT_SIZE,
            "font_color": self.FONT_COLOR,
            "bg_color": self.BG_COLOR,
            "bold": True
        }

        cell_formats = {
            "font_name": self.FONT_NAME,
            "font_size": self.FONT_SIZE,
        }

        wrote_report = False
        try:
            with pandas.ExcelWriter(
                self.filepath,
                engine="xlsxwriter",
                engine_kwargs={
                    "options": {
                        # Avoid /tmp exhaustion on systems with tiny tmpfs.
                        "tmpdir": excel_tmpdir,
                        # Disable auto URL conversion to reduce processing overhead.
                        "strings_to_urls": False,
                        # Prevent '='-prefixed user strings from being treated as formulas.
                        "strings_to_formulas": False,
                    }
                },
            ) as writer:
                used_sheetnames: set[str] = set()
                for dataframe in dataframe_objects:
                    if not dataframe["dataframe"].empty:
                        sheetname = self._unique_excel_sheet_name(
                            dataframe.get("sheetname", "Sheet"),
                            used_sheetnames,
                        )
                        df = self._sanitize_excel_dataframe(dataframe["dataframe"])

                        df.to_excel(writer, sheet_name=sheetname, index=False)

                        workbook = writer.book
                        worksheet = writer.sheets[sheetname]

                        # format workbook headers
                        formatted_headers = workbook.add_format(header_formats)
                        # format cell
                        formatted_cell = workbook.add_format(cell_formats)

                        # Apply a header format to the first row (A1: G1)
                        for col_num, value in enumerate(df.columns.values):
                            worksheet.write(0, col_num, value, formatted_headers)

                        # Apply a cell format to data rows
                        worksheet.set_column('A:ZZ', 15, formatted_cell)
                wrote_report = True
        except OSError as error:
            if getattr(error, "errno", None) == errno.ENOSPC:
                tmp_free = shutil.disk_usage(excel_tmpdir).free
                raise OSError(
                    errno.ENOSPC,
                    (
                        "No space left while writing XLSX report. "
                        f"Configured temp dir: '{excel_tmpdir}' (free={tmp_free} bytes)."
                    ),
                ) from error
            raise
        finally:
            self._cleanup_excel_tmpdir(excel_tmpdir)

        if wrote_report:
            self.print_info_message(
                message="Analyzed Vulnerabilities have been written to :",
                file_path=self.filepath)

    def save_to_csv(self, filename, content, *args):
        """ 
        Save contents to CSV file

        :param filename: name of the file the content is going to be saved to
        :param content: content to be saved
        :param args: extra argument if necessary
        """

        filename = self.get_file_basename(filename)
        try:
            target_path = self._safe_path(self.output_directory, filename)
            self._assert_not_symlink(target_path)
        except ValueError as error:
            self.print_error_message(
                message=f"Unsafe CSV output path rejected for '{filename}'",
                exception_error=error,
            )
            return
        file_path = str(target_path)

        # TODO: Remove CSV headers
        if "unresponsive_hosts" not in filename:
            # column_name = "Live Host IP Addresses"
            self.live_hosts_file = file_path

        else:
            # column_name = "Unresponsive IP Addresses"
            self.unresponsive_hosts_file = file_path

        # Ensure content is a list (handles single value or multiple values)
        if not isinstance(content, (list, tuple)):
            content = [content]

        # Flatten nested lists if present.
        deduplicated_ips = [
            str(item if not isinstance(item, (list, tuple)) else item[0]).strip()
            for item in content
            if item is not None and str(item).strip()
        ]
        if not deduplicated_ips:
            return

        # Load existing file content once, then keep an in-memory cache.
        cache = self._csv_cache.setdefault(file_path, set())
        if file_path not in self._csv_cache_loaded and self.file_exists(file_path):
            try:
                existing_df = self.read_csv(file_path, ip_list=True)
                cache.update(
                    str(ip).strip()
                    for ip in existing_df[0].to_list()
                    if ip is not None and str(ip).strip()
                )
            except Exception:
                # If the file is malformed/unreadable, keep going with append-only writes.
                pass
            self._csv_cache_loaded.add(file_path)
        elif file_path not in self._csv_cache_loaded:
            self._csv_cache_loaded.add(file_path)

        new_ips = [ip for ip in deduplicated_ips if ip not in cache]
        if not new_ips:
            return

        try:
            with self._open_secure_output_file(target_path, append=True) as csv_file:
                for ip in new_ips:
                    csv_file.write(f"{ip}\n")
        except OSError as error:
            self.print_error_message(
                message=f"Failed writing CSV output '{file_path}'",
                exception_error=error,
            )
            return

        cache.update(new_ips)

    def get_file_paths(self) -> dict:
        """Return stored file paths for live and unresponsive hosts"""
        return {
            "live_hosts": self.live_hosts_file,
            "unresponsive_hosts": self.unresponsive_hosts_file,
        }

    @staticmethod
    def read_csv(dataframe, **kwargs):
        """Handles reading of CSV files

        :param dataframe : The file to be read
        :param kwargs: Keyword Arguments
        :keyword header: True or False
        :keyword ip_list :True or False (handles file that have ips)
        """
        if "header" in kwargs:
            return pandas.read_csv(dataframe, header="infer")
        # utf-16 cp1252
        if kwargs.get("ip_list"):
            return pandas.read_csv(dataframe, encoding="ISO-8859-1", header=None)
        return pandas.read_csv(dataframe, encoding="ISO-8859-1")

    @staticmethod
    def read_excel_file(file, **kwargs):
        try:
            return pandas.read_excel(
                file,
                engine="openpyxl",
                **kwargs
            )
        except Exception as e:
            print(f"Error reading excel file: {e}")
            raise

    @staticmethod
    def get_file_extension(filename):
        # Split the filename into root and extension
        root, ext = os.path.splitext(filename)
        # Return the extension, excluding the dot
        return ext.lstrip(".")

    @staticmethod
    def append_to_sheets(data_frame: object, file: str):
        """Appends data to existing Workbook"""
        target_file = Path(file)
        FileHandler._assert_not_symlink(target_file)
        sheetname = FileHandler._sanitize_excel_sheet_name(
            data_frame.get("sheetname", "Sheet")
        )
        safe_df = FileHandler._sanitize_excel_dataframe(data_frame["dataframe"])
        with pandas.ExcelWriter(
                str(target_file), engine="openpyxl", mode="a", if_sheet_exists="replace"
        ) as writer:
            # Write new data frame to a new sheet
            safe_df.to_excel(
                writer, sheet_name=sheetname, index=False
            )

    @classmethod
    def _sanitize_excel_sheet_name(cls, raw_name: Any) -> str:
        """Return an Excel-safe sheet name (length and character constraints)."""
        candidate = str(raw_name or "").strip()
        if not candidate:
            candidate = "Sheet"

        cleaned = "".join("_" if ch in cls._EXCEL_INVALID_SHEET_CHARS else ch for ch in candidate)
        cleaned = " ".join(cleaned.split()).strip("'")
        if not cleaned:
            cleaned = "Sheet"

        return cleaned[: cls.EXCEL_SHEETNAME_MAX_LEN]

    @classmethod
    def _sanitize_excel_cell_value(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value

        stripped = value.lstrip()
        if stripped and stripped[0] in cls._EXCEL_FORMULA_PREFIXES:
            return f"'{value}"
        return value

    @classmethod
    def _sanitize_excel_dataframe(cls, dataframe: pandas.DataFrame) -> pandas.DataFrame:
        if dataframe is None or dataframe.empty:
            return dataframe

        safe_df = dataframe.copy()
        candidate_columns = safe_df.select_dtypes(include=["object", "string"]).columns
        for column in candidate_columns:
            safe_df[column] = safe_df[column].map(cls._sanitize_excel_cell_value)
        return safe_df

    @classmethod
    def _unique_excel_sheet_name(cls, raw_name: Any, used_names: set[str]) -> str:
        """Ensure the generated Excel sheet name is unique (case-insensitive)."""
        base = cls._sanitize_excel_sheet_name(raw_name)
        candidate = base
        index = 2

        while candidate.lower() in used_names:
            suffix = f" ({index})"
            max_base_len = max(1, cls.EXCEL_SHEETNAME_MAX_LEN - len(suffix))
            candidate = f"{base[:max_base_len]}{suffix}"
            index += 1

        used_names.add(candidate.lower())
        return candidate

    def _get_excel_tmpdir(self) -> str:
        """Return a writable temp directory on the project filesystem.

        xlsxwriter uses a temp directory during workbook creation. Defaulting to
        system /tmp can fail when /tmp is a small tmpfs.
        """
        temp_dir = Path(self.working_dir) / ".tmp" / "xlsxwriter"
        temp_dir.mkdir(parents=True, exist_ok=True)
        return str(temp_dir)

    @staticmethod
    def _cleanup_excel_tmpdir(excel_tmpdir: str) -> None:
        """Best-effort cleanup of temporary XLSX writer artifacts."""
        tmp_dir = Path(excel_tmpdir)
        if not tmp_dir.exists():
            return
        for child in tmp_dir.iterdir():
            try:
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
            except OSError:
                continue

    def _estimate_excel_write_bytes(self, dataframe_objects: list) -> int:
        """Estimate bytes needed for XLSX temp/output writes.

        The estimate intentionally uses headroom because xlsxwriter creates
        temporary files before finalizing the workbook.
        """
        estimated_df_bytes = 0
        for dataframe in dataframe_objects:
            df = dataframe.get("dataframe")
            if df is None or df.empty:
                continue
            estimated_df_bytes += int(df.memory_usage(index=True, deep=True).sum())

        # Keep a sane floor so tiny reports still require a minimal free-space check.
        floor_bytes = 64 * self.BYTES_PER_MB
        return max(floor_bytes, int(estimated_df_bytes * self.XLSX_HEADROOM_MULTIPLIER))

    def _warn_if_low_excel_space(self, dataframe_objects: list, excel_tmpdir: str) -> None:
        """Warn before XLSX generation when available space looks risky."""
        min_free_mb = self.DEFAULT_XLSX_MIN_FREE_MB
        env_override = os.getenv("PENTEST_XLSX_MIN_FREE_MB")
        if env_override:
            try:
                min_free_mb = max(1, int(env_override))
            except ValueError:
                pass

        estimated_required = self._estimate_excel_write_bytes(dataframe_objects)
        threshold = max(estimated_required, min_free_mb * self.BYTES_PER_MB)

        tmp_free = shutil.disk_usage(excel_tmpdir).free
        output_free = shutil.disk_usage(self.output_directory).free

        if tmp_free >= threshold and output_free >= threshold:
            return

        self.print_warning_message(
            (
                "Low disk space detected before XLSX export. "
                f"Estimated required ~{estimated_required // self.BYTES_PER_MB}MB, "
                f"threshold={threshold // self.BYTES_PER_MB}MB."
            ),
            file_path=(
                f"tmp_dir='{excel_tmpdir}' free={tmp_free // self.BYTES_PER_MB}MB | "
                f"output_dir='{self.output_directory}' free={output_free // self.BYTES_PER_MB}MB"
            ),
        )

    def get_last_unresponsive_ip(self, unresponsive_file):
        """
        Takes a file as an input, sorts the ips available in the list in ascending order
        get the last Ip on the list to use as start_ip

        """
        self.existing_unresponsive_ips = self.load_existing_ips(
            unresponsive_file)
        ip_list = list(self.existing_unresponsive_ips)
        # [Performance] Pass ipaddress.ip_address as a function reference rather
        # than wrapping it in a lambda — avoids creating a new lambda object per
        # element during the sort.
        sorted_ips = sorted(ip_list, key=ipaddress.ip_address)
        total = len(self.existing_unresponsive_ips)
        self.print_info_message("Total IPs loaded ", file_path=total)
        if sorted_ips:
            last_address = sorted_ips[-1]
            self.print_info_message(
                "Resuming scan from IP address : ", file_path=last_address)
            return last_address

    @staticmethod
    def load_existing_ips(datafile):
        existing_ips = set()
        with open(datafile, 'r') as file:
            for line in file:
                ip = line.strip()
                if ip:
                    existing_ips.add(ip)
        return existing_ips

    @staticmethod
    def concat_dataframes(df: list):
        """Concatenate data Frames"""
        return pandas.concat(df, ignore_index=True, axis=0)

    @staticmethod
    def get_file_basename(full_file_path):
        return os.path.basename(full_file_path)

    @staticmethod
    def append_to_txt(filename, content):
        """Update existing file"""
        prepared = FileHandler._prepare_text_for_write(
            content,
            beautify_structured=True,
            wrap_long_lines=False,
        )
        with FileHandler._open_secure_output_file(Path(filename), append=True) as file:
            file.write(prepared)
            if not prepared.endswith("\n"):
                file.write("\n")

    @staticmethod
    def _beautify_structured_text(content: Any) -> tuple[str, str]:
        return beautify_structured_text(content)

    @staticmethod
    def _prepare_text_for_write(
        content: Any,
        beautify_structured: bool = True,
        wrap_long_lines: bool = False,
    ) -> str:
        return prepare_text_for_write(
            content,
            beautify_structured=beautify_structured,
            wrap_long_lines=wrap_long_lines,
        )

    @staticmethod
    def read_last_line(filename) -> str:
        """
        Takes a filename containing a list of ips and returns
        the last ip address
        """
        with open(f"{filename}", "rb") as file:
            try:  # catch OSError in case of one line file
                file.seek(-2, os.SEEK_END)
                while file.read(1) != b"\n":
                    file.seek(-2, os.SEEK_CUR)
            except OSError:
                file.seek(0)
            last_line = file.readline().decode()
        return last_line

    @staticmethod
    def create_pd_dataframe(data: list, columns: list):
        """Create a pandas dataframe from a list of dictionaries"""
        return pandas.DataFrame(data, columns=columns)

    @staticmethod
    def read_all_lines(file):
        with open(file, "r") as file:
            return file.readlines()

    def remove_file(self, file):
        """Delete a file from system"""
        try:
            file_path = Path(file)
            file_path.unlink(missing_ok=True)
        except Exception as e:
            self.print_error_message(exception_error=e)

    @staticmethod
    def generate_unique_name(file, extension="txt") -> str:
        timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        removed_extension = Path(file).stem
        return f"{removed_extension}_{timestamp}.{extension}"

    @staticmethod
    def sort_dataframe(dataframe, order):
        return pandas.Categorical(dataframe, categories=order, ordered=True)
