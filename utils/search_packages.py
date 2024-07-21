class SearchPackages:
    """Class contains dependencies necessary for script operation"""

    def __init__(self, os_commands) -> None:
        self.command = os_commands
        self.packages = [
            {"name": "bbot", "command": "pipx install bbot"},
            {"name": "subfinder", "command": "sudo apt install subfinder"},
            {
                "name": "go",
                "command": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
            },
            {
                "name": "gowitness",
                "command": "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin",
            },
            {"name": "brutespray", "command": "sudo apt-get install brutespray"},
            {"name": "assetfinder", "command": "sudo apt install assetfinder"},
            {"name": "amass", "command": "sudo apt install amass"},
            {"name": "httpx-toolkit", "command": "sudo apt install httpx-toolkit"},
            {"name": "getallurls", "command": "sudo apt install getallurls"},
            {
                "name": "netexec",
                "command": "sudo apt install pipx git && pipx ensurepath && pipx install git+https://github.com/Pennyw0rth/NetExec",
            },
            {
                "name": "urlhunter",
                "command": "go install -v github.com/utkusen/urlhunter@latest && sudo cp ~/go/bin/urlhunter /usr/bin",
            },
            {
                "name": "exiftool",
                "command": "sudo apt-get -y install libimage-exiftool-perl",
            },
            {
                "name": "chad",
                "command": "pip3 install google-chad && pip3 install --upgrade google-chad && playwright install chromium",
            },
            {
                "name": "snallygaster",
                "command": "pip3 install snallygaster && sudo apt install python3-dnspython python3-urllib3 python3-bs4",
            },
            {"name": "parsero", "command": "sudo apt install parsero"},
            {
                "name": "subzy",
                "command": "go install -v github.com/luKaSikic/subzy@latest && sudo cp ~/go/bin/subzy /usr/bin",
            },
            {
                "name": "subjack",
                "command": "go install -v github.com/haccer/subjack@latest && sudo cp ~/go/bin/subjack /usr/bin",
            },
        ]
        self.to_install = self.get_missing_packages()

    def get_missing_packages(self) -> list:
        """Returns a list of objects containg missing packages
        that need to be installed and command to in
        stall them"""

        return [
            package
            for package in self.packages
            if self.command.run_os_commands(f"which {package['name']}").returncode == 0
        ]

    def update_packages(self, package) -> list:
        """Takes in package as a dictionary containing
        package name and command to install it
        """
        self.packages
