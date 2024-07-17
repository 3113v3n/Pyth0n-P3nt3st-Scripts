from __Handlers__.install_dependencies import run_os_commands


class LocateDependencies:
    def __init__(self) -> None:
        self.dependecies = [
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
        self.to_install = self.is_dependency_installed()

    def is_dependency_installed(self) -> list:
        """Returns a list of objects containg missing packages that need to be installed and command to install them"""
        missing_packages = []
        for dependency in self.dependecies:
            result = run_os_commands(f"which {dependency['name']}")
            if result.returncode != 0:
                missing_packages.append(dependency)
        return missing_packages

    def update_dependencies(self, package) -> list:
        """Takes in package as a dictionary containing
        package name and command to install it
        """
        self.dependecies.append(package)
        return self.dependecies
