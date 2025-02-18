from .colors import Bcolors


class DisplayMessages(Bcolors):
    def __init__(self):
        pass

    @staticmethod
    def success_message(message:str, **kwargs):
        """Prints out a success message
        :param message:  to print
               **kwargs:  keyword arguments to ensure different messages are printed accordingly
        """
        msg = f"{Bcolors.OKGREEN}[+] {message}{Bcolors.ENDC}"

        if kwargs.get("mobile_success"):
            msg = (f"{Bcolors.WARNING}[+]{Bcolors.ENDC} {message}\n"
                   f"{Bcolors.OKGREEN}{Bcolors.UNDERLINE}{kwargs["mobile_success"]}{Bcolors.ENDC}")

        print(msg)
