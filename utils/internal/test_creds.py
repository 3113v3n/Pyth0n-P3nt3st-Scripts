import time
from datetime import datetime
# from handlers import DisplayHandler
from ..shared import Commands
from ..shared.colors import Bcolors


class CredentialsUtil(Bcolors):
    """Test Found credentials against a particular protocol"""
    MAX_ATTEMPTS = 2
    SUCCESS_DECORATOR = "[+]"
    LOGON_FAILURE_DECORATOR = "[-]"
    LOGON_FAILURE_TEXT = [
        "STATUS_LOGON_FAILURE",
        "STATUS_LOGON_TYPE_NOT_GRANTED",
        "STATUS_MORE_PROCESSING_REQUIRED",
        "STATUS_PASSWORD_EXPIRED"
    ]
    LOGON_SUCCESS_TEXT = ["(Pwn3d!)", "", "(nla:True)"]

    def __init__(self):
        super().__init__()

        self.creds_file = ""
        self.target = ""
        self.domain = ""
        self.log_file = "Cred_test.log"
        self._protocol = "smb"
        self.timer_delay = 5
        self.file_delimiter = ":"
        self.attempts = 0
        self.tested_accounts = {}
        self.output_file = ""
        self.run_command = Commands()

    def split_pass_file(self):
        """Splits userpass file into individual usernames and passwords
        userpass file format [username:password]
        """
        try:
            user_pass = {}
            with open(self.creds_file, "r") as creds:
                for line in creds:
                    if not line.strip():
                        continue
                    try:
                        username, password = line.strip().split(":")
                        user_pass[username] = password
                    except ValueError:
                        print(
                            f"[-] Skipping malformed line in {self.creds_file}:{line.strip()}")
        except FileNotFoundError:
            print(f"[+] Credentials file {self.creds_file} not found")
        return user_pass

    def test_credentials(
            self,
            target: str,
            domain: str,
            output_file,
            passlist,
            save_dir):
        """Test user credentials against a particular protocol

        :params     target:            IP address of target to test
                    domain:            Client domain being tested
                    output_file:        Defaults to Successful_Logins.txt for successful tests
                                         and Cred_test.log for full log of scan
                    passlist:            File containing your passwords to test
        : returns:
                            Log file containing test results
        """

        self.target = target
        self.domain = domain
        self.output_file = output_file
        self.creds_file = passlist
        user_pass_list = self.split_pass_file()
        date = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")

        # Initial message
        start_message = f"\nStarting credential test against {self.target} on Protocol {self._protocol} at {date}\n"
        print(start_message)
        with open(f"{save_dir}/{self.log_file}", "a") as file:
            file.write(f"{start_message}\n")

        if not user_pass_list:
            print("[-] No valid credentials found to test.")
            return

        for username, password in user_pass_list.items():
            # Skip tested usernames
            if username in self.tested_accounts:
                # write to log file here
                continue

            self.run_nxc(username, password, self.domain, save_dir)
            self.tested_accounts[username] = True

    def run_nxc(self, user, passwd, domain, save_dir):
        command = ["nxc", self._protocol, self.target,
                   "-u", user, "-p", passwd]
        if domain:
            # if domain is provided
            command.extend(["-d", domain])

        process = self.run_command.run_nxc_command(command)

        with open(f"{save_dir}/{self.log_file}", 'a') as logfile:

            for line in process.stdout:
                line = line.strip()
                text_to_print = self.format_text_output(line)
                print(text_to_print)
                if self.SUCCESS_DECORATOR in line:  # Check if pawned
                    # Write successful Logins to file
                    with open(self.output_file, 'a') as success:
                        success.write(f"{line}\n")

                logfile.write(f"{line}\n")

        process.wait()
        if process.returncode != 0:
            print(f"[!] nxc exited with error code {process.returncode}")

    @staticmethod
    def get_string_from_list(my_list: list, sentence: str) -> bool:
        for word in my_list:
            return word in sentence

    def format_text_output(self, text):
        # format string
        # Clean extra spaces
        cleaned_line = " ".join(text.split())

        # check if line contains [-] and STATUS_LOGON_FAILURE
        if self.LOGON_FAILURE_DECORATOR in cleaned_line and self.get_string_from_list(self.LOGON_FAILURE_TEXT, cleaned_line):
            colored_line = self.handle_colored_text(
                cleaned_line,
                self.LOGON_FAILURE_DECORATOR,
                self.LOGON_FAILURE_TEXT,
                self.WARNING,
                self.ENDC,
                self.FAIL,
                self.handle_string_replace
            )
        elif self.SUCCESS_DECORATOR in cleaned_line and self.get_string_from_list(self.LOGON_SUCCESS_TEXT, cleaned_line):
            colored_line = self.handle_colored_text(
                cleaned_line,
                self.SUCCESS_DECORATOR,
                self.LOGON_SUCCESS_TEXT,
                self.OKGREEN,
                self.ENDC,
                self.WARNING,
                self.handle_string_replace
            )
        else:
            colored_line = cleaned_line
        return colored_line

    @staticmethod
    def handle_colored_text(
            cleaned_line: str,
            decorator: str,
            text_to_colour: str,
            dec_color_start: str,
            color_end: str,
            txt_color_start: str,
            handle_string_replace: callable) -> str:
        # split the line into parts
        parts = cleaned_line.split(decorator)
        if len(parts) > 1:
            # Color decorator and text
            colored_line = (f"{parts[0]}{dec_color_start}{decorator}{color_end} {handle_string_replace(
                parts[1], text_to_colour, txt_color_start, color_end)}"
            )
        else:
            colored_line = cleaned_line  #

        return colored_line

    @staticmethod
    def handle_string_replace(
            full_text: str,
            possible_vars: list,
            start_color: str,
            end_color: str) -> str:
        sentence = full_text
        for word in possible_vars:
            if word in sentence:
                colored_word = f"{start_color}{word}{end_color}"
                sentence = sentence.replace(word, colored_word)
        return sentence
