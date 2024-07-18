import subprocess


class Commands:
    def __init__(self) -> None:
        pass

    def run_os_commands(self, command):
        """Executes shell commands"""
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
