import os
import subprocess
import platform


class Commands:
    """Class handles commands that will be used by the script"""

    @staticmethod
    def run_os_commands(command):
        """Executes shell commands such as [apt and sudo]"""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}\nError: {e.stderr}")
            raise Exception(e.stderr)
        return result

    @staticmethod
    def run_git_cmd(git_command):
        try:
            print(f"running command:\n{git_command}\n\n")
            subprocess.run(git_command, check=True)
            print("Nuclei template Installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install Nuclei templates: {e}")
            return False

    @staticmethod
    def get_process_output(command):
        return subprocess.getoutput(command)

    @staticmethod
    def auto_enter_commands(command):
        """Automatically press enter when prompted by script"""
        try:
            cmd = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True
            )
            cmd.communicate(b"\n")  # Simulate pressing enter on the keyboard
        except TypeError:
            print(str(TypeError))

    @staticmethod
    def ping_hosts(host):
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

    @staticmethod
    def clear_screen():
        """Clear screen"""
        return os.system('cls' if os.name == 'nt' else 'clear')
 
