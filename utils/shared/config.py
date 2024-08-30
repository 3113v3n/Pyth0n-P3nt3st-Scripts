from .colors import bcolors


class Config:

    test_domains = [
        # {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing", "alias": "internal", "icon": "🖥️"},
        # {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
        {"domain": "Vulnerability Analysis", "alias": "va", "icon": "🔎"},
    ]
    scan_modes = ["SCAN", "RESUME"]
    domain_select_error = f"\n{bcolors.FAIL}[!]{bcolors.ENDC} Please choose one of: \n"
    internal_mode_choice = (
        f"\n[+] What mode would you like to run the scan with [{bcolors.OKCYAN} SCAN | RESUME {bcolors.ENDC}]"
        f"\n{bcolors.OKCYAN}SCAN{bcolors.ENDC} : scan new subnet\n"
        f"{bcolors.OKCYAN}RESUME{bcolors.ENDC} : resume previous scan\n "
        f"\n(In case you want to {bcolors.BOLD}RESUME{bcolors.ENDC} a scan,"
        f"please remember to {bcolors.BOLD}{bcolors.WARNING}manually update "
        f"the file{bcolors.ENDC}{bcolors.ENDC} \nwith the last scanned ip to "
        "allow resume scan from last scanned ip rather than last found ip address)\n"
        "\n Enter mode: ==> "
    )
    internal_choice_error = f"\n{bcolors.FAIL}[!]{bcolors.ENDC} Please select one of: [ {bcolors.OKCYAN}SCAN | RESUME{bcolors.ENDC} ]"
    external_packages = [
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
    internal_packages = [
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
    mobile_packages = [
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
    va_headers = [
        "CVE",
        "Risk",
        "Host",
        "Protocol",
        "Port",
        "Name",
        "Synopsis",
        "Description",
        "Solution",
        "See Also",
        "Plugin Output"
    ]
    column_mismatch_error = f"{bcolors.FAIL}{bcolors.BOLD}[!]Column mismatch between files. Ensure all files have the same number of columns {bcolors.ENDC}"
