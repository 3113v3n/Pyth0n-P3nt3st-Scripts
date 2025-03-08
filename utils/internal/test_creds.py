import time
from datetime import datetime
# from handlers import DisplayHandler
import subprocess


class CredentialsUtil():
    """Test Found credentials against a particular protocol"""
    MAX_ATTEMPTS = 2
    SMB_SUCCESS = "(Pwn3d!)"
    RDP_SUCCESS = "(nla:True)"
    SUCCESS_DECORATOR = "[+]"
    LOGON_FAILURE_DECORATOR = "[-]"
    LOGON_FAILURE_TEXT = "STATUS_LOGON_FAILURE"

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def __init__(self):
        self.creds_file = "usrpass.txt"
        self.target = "192.168.2.29"
        self.domain = ""
        self.log_file = "Cred_test.log"
        self.protocol = "smb"
        self.timer_delay = 5
        self.file_delimiter = ":"
        self.attempts = 0
        self.tested_accounts = {}
        self.output_file = "Successful_Logins.txt"

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

    def test_credentials(self, target, domain, **kwargs):
        """Test user credentials against a particular protocol

        :params     target:         IP address of target to test
                    domain:         Client domain being tested
                    protocol: 
                                     [smb]
        : returns:
                            Log file containing test results
        """
        if kwargs.get("protocol"):
            self.protocol = kwargs.get("protocol")

        self.target = target
        self.domain = domain
        user_pass_list = self.split_pass_file()
        date = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")

        # Initial message
        start_message = f"\nStarting credential test against {self.target} on Protocol {self.protocol} at {date}\n"
        print(start_message)
        with open(self.log_file, "a") as file:
            file.write(f"{start_message}\n")

        if not user_pass_list:
            print("[-] No valid credentials found to test.")
            return

        for username, password in user_pass_list.items():
            # Skip tested usernames
            if username in self.tested_accounts:
                # write to log file here
                continue

            self.run_nxc(username, password, self.domain)
            self.tested_accounts[username] = True

    def run_nxc(self, user, passwd, domain):
        command = ["nxc", self.protocol, self.target,
                   "-u", user, "-p", passwd]
        if domain:
            # if domain is provided
            command.extend(["-d", domain])

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        with open(self.log_file, 'a') as logfile:

            for line in process.stdout:
                line = line.strip()
                text_to_print = self.format_text_output(line)
                print(text_to_print)
                if self.SMB_SUCCESS in line:  # Check if pawned
                    # Write successful Logins to file
                    with open(self.output_file, 'a') as success:
                        success.write(f'{line}\n')

                logfile.write(f'{line}\n')

        process.wait()
        if process.returncode != 0:
            print(f"[!] nxc exited with error code {process.returncode}")

    def format_text_output(self, text):
        # format string
        # Clean extra spaces
        cleaned_line = " ".join(text.split())

        # check if line contains [-] and STATUS_LOGON_FAILURE
        if self.LOGON_FAILURE_DECORATOR in cleaned_line and self.LOGON_FAILURE_TEXT in cleaned_line:
            colored_line = self.handle_colored_text(
                cleaned_line,
                self.LOGON_FAILURE_DECORATOR,
                self.LOGON_FAILURE_TEXT,
                self.WARNING,
                self.ENDC,
                self.FAIL
            )
        elif self.SUCCESS_DECORATOR in cleaned_line and self.SMB_SUCCESS in cleaned_line:
            colored_line = self.handle_colored_text(
                cleaned_line,
                self.SUCCESS_DECORATOR,
                self.SMB_SUCCESS,
                self.OKGREEN,
                self.ENDC,
                self.WARNING
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
            txt_color_start: str) -> str:
        # split the line into parts
        parts = cleaned_line.split(decorator)
        if len(parts) > 1:
            # Color decorator and text
            colored_line = (f"{parts[0]}{dec_color_start}{decorator}{color_end} {parts[1].replace(
                text_to_colour,
                f'{txt_color_start}{text_to_colour}{color_end}')}\n"
            )
        else:
            colored_line = cleaned_line  #

        return colored_line


if __name__ == "__main__":
    cred_test = CredentialsUtil()
    cred_test.test_credentials(
        "192.168.2.29", "testdomain.co.ke", protocol="smb")
