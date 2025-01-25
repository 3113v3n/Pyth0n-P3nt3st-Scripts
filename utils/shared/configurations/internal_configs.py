from ..colors import Bcolors


class InternalConfigs():
    def __init__(self):
        pass
    internal_packages = [
        # Internal
        {
            "name": ["netexec"],
            "command": "multiple",
            "cmd": " pipx install git+https://github.com/Pennyw0rth/NetExec",
        },
        {
            "name": ["exiftool"],
            "command": "sudo apt-get -y install libimage-exiftool-perl",
        },
    ]
    internal_mode_choice = (
        f"\n[+] Select scan mode: [{Bcolors.OKCYAN}SCAN | RESUME{Bcolors.ENDC}]"
        f"\n\n{Bcolors.OKCYAN}SCAN{Bcolors.ENDC}: Scan a new subnet."
        f"\n{Bcolors.WARNING}RESUME{Bcolors.ENDC}: Continue a previous scan. "
        "\n\n Enter mode: ==> "
    )
    internal_choice_error = (
        f"\n{Bcolors.FAIL}[!]{Bcolors.ENDC} Please select one of: [ {
            Bcolors.OKCYAN}SCAN | RESUME"
        f"{Bcolors.ENDC} ]"
        "\n\n Enter mode: ==> "
    )
