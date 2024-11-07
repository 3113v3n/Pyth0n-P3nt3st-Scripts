from .colors import bcolors


class Config:
    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing", "alias": "internal", "icon": "🖥️"},
        #{"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
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

        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
        },
        {
            "name": ["gowitness"],
            "command": "multiple",
            "cmd": "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin",
        },

        {
            "name": ["getallurls", "httpx-toolkit", "assetfinder", "brutespray", "subfinder"],
            "command": "sudo apt install"},
        {
            "name": ["urlhunter"],
            "command": "multiple",
            "cmd": "go install -v github.com/utkusen/urlhunter@latest &&  sudo cp ~/go/bin/urlhunter /usr/bin",
        },
        {
            "name": ["chad"],
            "command": "multiple",
            "cmd": "pip3 install google-chad && pip3 install --upgrade google-chad && playwright install chromium",
        },
        {"name": ["bbot"], "command": "pipx install"},
        {
            "name": ["python3-dnspython", "python3-urllib3", "python3-bs4"],
            "command": "sudo apt install"},
        {
            "name": ["snallygaster"],
            "command": "pip3 install snallygaster ",
        },
        {"name": ["parsero"], "command": "sudo apt install "},
        {
            "name": ["subzy"],
            "command": "multiple",
            "cmd": "go install -v github.com/luKaSikic/subzy@latest && sudo cp ~/go/bin/subzy /usr/bin",
        },
        {
            "name": ["subjack"],
            "command": "multiple",
            "cmd": "go install -v github.com/haccer/subjack@latest && sudo cp ~/go/bin/subjack /usr/bin",
        },
    ]
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
    general_packages = [
        {"name": ["pipx"],
         "command": "multiple",
         "cmd": "sudo apt install pipx git && pipx ensurepath"}
    ]
    mobile_packages = [
        # Mobile
        ## Install on Device
        # 1. WiFi ADB
        # 2. Magisk Frida / SQlite
        # 3. Drozer
        {
            "name": ["apktool"],
            "command": "multiple"
            , "cmd": "sudo apt -y install aapt \
                wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool \
                chmod +x apktool && cp apktool /usr/local/bin/apktool \
                wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar \
                chmod +x apktool.jar && cp apktool.jar /usr/local/bin/apktool.jar",
        },
        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
        },
        {
            "name": ["adb", "dex2jar", "nuclei", "radare2", "libusbmuxd-tools", "sqlite3", "sqlitebrowser",
                     "xmlstarlet", "apksigner", "zipalign"],
            "command": "apt-get -y install "
        },
        {

            "name": ["frida-tools", "objection", "file-scraper"],
            "command": "pipx install"
        },
        {"name": ["java"], "command": "sudo apt install default-jdk -y"},
        {
            "name": ["property-lister"],
            "command": "pipx install --upgrade ",
        },
        {"name": ["plistutil"], "command": "apt-get -y install "},
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
        "Plugin Output",
    ]
    column_mismatch_error = f"{bcolors.FAIL}{bcolors.BOLD}[!]Column mismatch between files. Ensure all files have the same number of columns {bcolors.ENDC}"

    def filter_conditions(vulnerabilities, regex_word):
        return {
            "ssl_condition": (vulnerabilities["Name"].notna())
                             & (vulnerabilities["Name"].str.contains(regex_word("SSL"), regex=True))
                             | (vulnerabilities["Name"].str.contains(regex_word("TLS"), regex=True))
                             | (vulnerabilities["Name"].str.contains(regex_word("POODLE"), regex=True)),
            "missing_patch_condition": ((vulnerabilities["Solution"].notna()))
                                       & (
                                           vulnerabilities["Solution"].str.contains(
                                               regex_word("Update"), regex=True
                                           )
                                       )
                                       | (vulnerabilities["Solution"].str.contains(regex_word("patches")))
                                       | (vulnerabilities["Solution"].str.contains(regex_word("updates")))
                                       | (vulnerabilities["Solution"].str.contains(regex_word("security update")))
                                       | (
                                           vulnerabilities["Solution"].str.contains(
                                               regex_word("Microsoft has released")
                                           )
                                       ),
            "unsupported_software": (vulnerabilities["Solution"].notna())
                                    & (
                                        vulnerabilities["Solution"].str.contains(
                                            regex_word("Upgrade", is_extra=True, second_term="Update"),
                                            regex=True,
                                        )
                                    )
                                    | (
                                        vulnerabilities["Name"].str.contains(
                                            regex_word("no longer supported"), regex=True
                                        )
                                    )
                                    | (
                                        vulnerabilities["Description"].str.contains(
                                            regex_word("no longer supported"), regex=True
                                        )
                                    )
                                    | (
                                        vulnerabilities["Name"].str.contains(
                                            regex_word("unsupported"), regex=True
                                        )
                                    )
                                    | (
                                        vulnerabilities["Solution"].str.contains(
                                            regex_word("unsupported"), regex=True
                                        )
                                    )
                                    | (
                                        vulnerabilities["Solution"].str.contains(
                                            regex_word("Unsupported Version"), regex=True
                                        )
                                    )
                                    | (
                                        vulnerabilities["Name"].str.contains(
                                            regex_word("Unsupported Version"), regex=True
                                        )
                                    ),
            "kaspersky_condition": (vulnerabilities["Name"].notna())
                                   & vulnerabilities["Name"].str.contains(regex_word("Kaspersky"), regex=True),
            "insecure_condition": (vulnerabilities["Name"].notna())
                                  & vulnerabilities["Name"].str.contains(
                regex_word("Insecure Windows Service"), regex=True
            ),
            "winverify_condition": (vulnerabilities["Name"].notna())
                                   & vulnerabilities["Name"].str.contains(
                regex_word("WinVerifyTrust"), regex=True
            ),
            "unquoted_condition": (vulnerabilities["Name"].notna())
                                  & vulnerabilities["Name"].str.contains(
                regex_word("Unquoted Service Path"), regex=True
            ),
            "smb_condition": (vulnerabilities["Name"].notna())
                             & vulnerabilities["Name"].str.contains(regex_word("SMB"), regex=True),
            "speculative_condition": (vulnerabilities["Name"].notna())
                                     & vulnerabilities["Name"].str.contains(
                regex_word("Windows Speculative"), regex=True
            ),
            "AD_condition": (vulnerabilities["Name"].notna())
                            & vulnerabilities["Name"].str.contains(
                regex_word("AD Starter"), regex=True
            ),
            "defender_condition": (vulnerabilities["Synopsis"].notna())
                                  & vulnerabilities["Synopsis"].str.contains(
                regex_word("antimalware"), regex=True
            ),
            "rdp_condition": (vulnerabilities["Name"].notna())
                             & (
                                 vulnerabilities["Name"].str.contains(
                                     regex_word("Terminal Services"), regex=True
                                 )
                             )
                             | (
                                 vulnerabilities["Name"].str.contains(
                                     regex_word("Remote Desktop Protocol"), regex=True
                                 )
                             ),
            "compliance_condition": (vulnerabilities["Risk"].notna())
                                    & (vulnerabilities["Risk"].str.contains(regex_word("FAILED"), regex=True))
                                    & (
                                        vulnerabilities["Synopsis"].str.contains(
                                            regex_word("Compliance checks"), regex=True
                                        )
                                    ),
            "ssh_condition": (vulnerabilities["Synopsis"].notna())
                             & vulnerabilities["Synopsis"].str.contains(
                regex_word("SSH server"), regex=True
            ),
            "telnet_condition": (vulnerabilities["Name"].notna())
                                & vulnerabilities["Name"].str.contains(
                regex_word("Telnet Server"), regex=True
            ),
            "information_condition": (vulnerabilities["Name"].notna())
                                     & vulnerabilities["Name"].str.contains(
                regex_word("Information Disclosure"), regex=True
            ),
            "web_condition": (vulnerabilities["Name"].notna())
                             & (vulnerabilities["Name"].str.contains(regex_word("Web"), regex=True))
                             | (
                                 vulnerabilities["Description"].str.contains(
                                     regex_word("web server"), regex=True
                                 )
                             ),
            "rce_condition": (vulnerabilities["Description"].notna())
                             & (
                                 vulnerabilities["Description"].str.contains(
                                     regex_word("remote code execution"), regex=True
                                 )
                             ),
        }

    # MOBILE ANALYSIS CONSTANTS
    # Define regex patterns as raw strings for better readability and handling
    IOS_FILE_SEARCH = r"hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView"
    BEARER_REGEX = r"[^\w\d]+(basic|bearer)\s.+"
    HARDCODED_REGEX = r'(\?access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)\w*(?:"\s*:\s*|\s*=).+'
    HARDCODED_REGEX_2 = r"([^\w\d]+(to(_|\s)do|todo|note)\s|//|/\*|\*/).+"
    BASE64_REGEX = r"(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}=|[a-zA-Z0-9\+\/]{2}==)"
    IP_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    URL_REGEX = r"\w+://[\w\-\.\@\:\/\?\=\%\&\#]+"
    DEEPLINKS_IGNORE_REGEX = r"\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)"
