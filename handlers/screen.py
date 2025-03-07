from .messages import DisplayHandler
from utils.shared.loader import Loader


class ScreenHandler(DisplayHandler):
    def __init__(self):
        super().__init__()

    @staticmethod
    def create_menu_selection(
            menu_selection: str,
            options: list | tuple,
            check_range_string: str,
            check_range_function: callable,
            start_color: str,
            end_color: str,
            **kwargs):
        print(menu_selection)
        for option in options:
            # Ensure both scanner menu and file extension are sorted for
            display_option = option["name"] if "scanner" in kwargs else option.upper(
            )
            print(f" {start_color}[{options.index(option) + 1}]{end_color}"
                  f" {display_option}"
                  )
        return check_range_function(f"\n {check_range_string}", options)

    @staticmethod
    def show_loader(
        message: str,
        end_message: str,
        spinner_type: str = "dots",
        continuous: bool = False,
        timer=30
    ):
        """Display Loading functionality to a user
        :param message: message to display
        :param end_message: a message to display after loading complete
        :param continuous: Boolean to control timer
        :param spinner_type: type of spinner to use
        """
        loader = Loader(
            desc=message,
            end=end_message,
            spinner_type=spinner_type,
            continuous=continuous,
            timer=timer
        )
        loader.start()
        if continuous:
            return loader  # return loader only for continuous loading

        return None

    def get_file_path(self, prompt: str, check_folder_exists: callable):
        """Get and validate a file path from user"""
        while True:
            file_path = input(prompt).strip()
            if not file_path:
                self.print_warning_message("Path cannot be empty")

                continue
            if not check_folder_exists(file_path):
                self.print_error_message("No such file/folder exists")
                continue
            return file_path

    def get_output_filename(self, prompt: str = "\n[+] Please enter the output filename: "):
        """Get output filename from user"""

        while True:
            filename = input(prompt).strip()
            if not filename:
                self.print_warning_message("Filename cannot be empty")
                continue
            return filename

    def get_user_input(self, prompt: str):
        """Get user input
        :param prompt: Text to display to user
        : return user input
        """
        while True:
            user_input = input(prompt).strip().lower()
            if not user_input:
                self.print_warning_message("Input cannot be empty")
                continue
            return user_input

    @staticmethod
    def display_files_onscreen(
            directory: str,
            display_saved_files: callable,
            **kwargs) -> tuple:
        """Display files in directory with extension filter"""
        files = display_saved_files(
            directory,
            scan_extension=kwargs.get("scan_extension"),
            resume_scan=kwargs.get("resume_scan", False),
            display_applications=kwargs.get("display_applications", False)
        )
        if not files:
            raise FileNotFoundError(f"\n[!] No files found in {directory}")
        return files
