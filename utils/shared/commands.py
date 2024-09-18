import os
import subprocess
import platform


class Commands:
    """Class handles commands that will be used by the script"""

    def __init__(self) -> None:
        pass

    def run_os_commands(self, command):
        """Executes shell commands such as [apt and sudo]"""

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
        )
        return result

    def get_process_output(self, command):
        return subprocess.getoutput(command)

    def auto_enter_commands(self, command):
        """Automatically press enter when prompted by script"""
        try:
            cmd = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True
            )
            cmd.communicate(b"\n")  # Simulate pressing enter on the keyboard
        except TypeError:
            print(str(TypeError))

    def ping_hosts(self, host):
        """
        Returns True if host (str) responds to a ping request.
        Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
        """
        # Option for the number of packets as a function of
        param = "-n" if platform.system().lower() == "windows" else "-c"

        try:
            # Building the command. Ex: "ping -c 1 google.com"
            command = ["ping", param, "1", host]

            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

        except Exception as e:
            print(e)
            return False

    def clear_screen(self):
        """Clear screen"""
        return os.system("clear")
