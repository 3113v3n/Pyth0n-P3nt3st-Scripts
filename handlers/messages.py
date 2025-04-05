from utils.shared.colors import Bcolors


class DisplayHandler(Bcolors):
    def __init__(self):
        super().__init__()
        pass

    @staticmethod
    def print_debug_message(message: str):
        """Print debug messages for debugging purposes
        :message: message to print
        """
        print(
            f" {Bcolors.HEADER}[#] DEBUG:{Bcolors.ENDC} "
            f"\n{Bcolors.WARNING}{message}{Bcolors.ENDC}"
        )

    @staticmethod
    def print_success_message(message: str, **kwargs):
        """Prints out a success message
        :param message:  to print
               **kwargs:  keyword arguments to ensure different messages are printed accordingly
                - mobile_success: shows the directory where mobile scans are stored
                - extras: any extra data to print
                - flush: flush the message
        """
        msg = f"\n{Bcolors.OKGREEN}[+] {message}{Bcolors.ENDC}"

        if kwargs.get("mobile_success"):
            msg = (
                f"\n{Bcolors.WARNING}[+]{Bcolors.ENDC} {message}\n"
                f"{Bcolors.OKGREEN}{Bcolors.UNDERLINE}{kwargs["mobile_success"]}{Bcolors.ENDC}\n"
            )
        elif kwargs.get("extras"):
            extra_data = kwargs["extras"]
            msg = f"{msg}{extra_data}\n\n"
        elif kwargs.get("flush"):
            # Default to empty string if absent
            extra_data = kwargs.get("extras", "")
            msg = f"{msg}{extra_data}"
            return print(msg, flush=kwargs["flush"])

        print(msg)

    @staticmethod
    def print_error_message(message: str = "Error ", **kwargs):
        """Prints out error messages
        :param message:  to print
                **kwargs: Keyword arguments to handle exception type errors
                    - exception_error: error raised from exceptions
        """
        msg = f"\n{Bcolors.FAIL}[!] Error: {message} {Bcolors.ENDC}"

        if kwargs.get("exception_error"):
            error = kwargs["exception_error"]
            msg = f"\n{Bcolors.FAIL}[!] {message}: {str(error)}{Bcolors.ENDC}"

        print(msg)

    @staticmethod
    def print_warning_message(message: str, **kwargs):
        """Prints out warning messages
        :param message:  to print
                **kwargs: Keyword arguments to handle different print actions
                    - data = list of IPs
                    - flush = Boolean value to flush messages
                    - file_path = file path
        """
        msg = f"\n{Bcolors.WARNING}[-] Warning: {message} {Bcolors.ENDC}\n"
        if kwargs.get("flush"):
            msg = f"\n{Bcolors.HEADER}[#] Summary: {message} {Bcolors.ENDC}\n"
            ip_list = kwargs["data"]
            flush = kwargs["flush"]
            return print(msg, ip_list, flush=flush)
        if kwargs.get("file_path"):
            path = kwargs["file_path"]
            msg = f"{msg}{path}"

        print(msg)

    @staticmethod
    def print_trace_message(message: str):
        """print trace messages on terminal"""
        msg = f"\n {Bcolors.HEADER}[TRACE]{Bcolors.ENDC} {message}"
        print(msg)

    @staticmethod
    def print_info_message(message: str, **kwargs):
        """Prints out info messages
        :param message:  to print
            **kwargs: Keyword arguments to handle different print actions
                - flush = Boolean value to flush messages
                - file_path: file path to VA scans
                - file : files being scanned in mobile module
        """
        msg = f"\n{Bcolors.OKCYAN}[*] Info: {message} {Bcolors.ENDC}\n"
        if kwargs.get("flush"):
            flush = kwargs["flush"]
            encoded_string = kwargs.get("encoded_string", "")
            msg = f"{msg}{encoded_string}"
            return print(msg, flush=flush)

        if kwargs.get("file_path"):
            path = kwargs["file_path"]
            msg = f"\n{Bcolors.HEADER}[-] Info: {message} {Bcolors.ENDC}\n{path}"

        elif kwargs.get("file"):
            msg = f"{msg}{kwargs['file']}"

        print(msg)

    @staticmethod
    def print_selection_items(file: dict, index: int) -> None:
        """Print items for selection on screen
        :param file: file dictionary containing filename and full file path
        :param index: index of the item to print
        """
        filename = f" {Bcolors.BOLD}{Bcolors.WARNING}{file['filename']}{Bcolors.ENDC}"
        display_str = (
            f"Enter [{Bcolors.OKGREEN}{Bcolors.BOLD}{index}{Bcolors.ENDC}] to select"
            f"{filename}"
        )
        print(display_str)
