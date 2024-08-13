class PackageHandler:
    """Handles package related actions such as installation of missing Packages"""

    def __init__(self, command, colors) -> None:
        self.command = command()
        self.colors = colors
        self.external_packages = [
            # External
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
                "command": "go install -v github.com/utkusen/urlhunter@latest &&  sudo cp ~/go/bin/urlhunter /usr/bin",
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
        self.internal_packages = [
            # Internal
            {
                "name": "netexec",
                "command": "sudo apt install pipx git && pipx ensurepath && pipx install git+https://github.com/Pennyw0rth/NetExec",
            },
            {
                "name": "exiftool",
                "command": "sudo apt-get -y install libimage-exiftool-perl",
            },
        ]
        self.mobile_packages = [
            # Mobile
            {
                "name": "apktool",
                "command": "sudo apt -y install aapt \
                wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool \
                chmod +x apktool && cp apktool /usr/local/bin/apktool \
                wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar \
                chmod +x apktool.jar && cp apktool.jar /usr/local/bin/apktool.jar",
            },
            {
                "name": "dependencies",
                "command": "apt-get -y install \
                 adb dex2jar jadx nuclei radare2 sqlite3 \
                     sqlitebrowser xmlstarlet apksigner \
                         zipalign pip3 install frida-tools objection file-scraper",
            },
        ]

    def get_missing_packages(self, test_domain) -> list:
        """Returns a list of objects containg missing packages
        that need to be installed and command to in
        stall them"""
        if test_domain == "mobile":
            packages = self.mobile_packages
        elif test_domain == "internal":
            packages = self.internal_packages
        elif test_domain == "external":
            packages = self.external_packages

        return [
            package
            for package in packages
            if self.command.run_os_commands(f"which {package['name']}").returncode != 0
        ]

    def install_packages(self, packages):
        """Loops through an array of packages and installs them"""
        for package in packages:
            print(
                f"[+] Installing the following package:\n{self.colors.OKCYAN}{package['name']}{self.colors.ENDC}\n"
            )
            # self.command.run_os_commands(command=package["command"])
        print(f"\n{self.colors.OKGREEN}[+] Installation complete{self.colors.ENDC}")
