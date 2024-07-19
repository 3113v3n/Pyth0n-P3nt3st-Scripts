import subprocess


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
        # if result.returncode == 0:
        #     print(result.stdout.strip())
        return result
    
