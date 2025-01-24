from .colors import Bcolors


class Config:
    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing", "alias": "internal", "icon": "🖥️"},
        # {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
        {"domain": "Vulnerability Analysis", "alias": "va", "icon": "🔎"},
        {"domain": "Exit Program", "alias": "exit", "icon": ""},
    ]
    scan_modes = ["SCAN", "RESUME"]
    domain_select_error = f"\n{Bcolors.FAIL}[!]{Bcolors.ENDC} Please choose one of: \n"
    internal_mode_choice = (
        f"\n[+] Select scan mode: [{Bcolors.OKCYAN}SCAN | RESUME{Bcolors.ENDC}]"
        f"\n\n{Bcolors.OKCYAN}SCAN{Bcolors.ENDC}: Scan a new subnet."
        f"\n{Bcolors.WARNING}RESUME{Bcolors.ENDC}: Continue a previous scan. "
        "\n\n Enter mode: ==> "
    )
    internal_choice_error = (
        f"\n{Bcolors.FAIL}[!]{Bcolors.ENDC} Please select one of: [ {Bcolors.OKCYAN}SCAN | RESUME"
        f"{Bcolors.ENDC} ]"
        "\n\n Enter mode: ==> "
    )
    vulnerability_scanners = [
        {"name": "Nessus Scanner", "alias": "nessus"},
        {"name": "Insight VM", "alias": "rapid"},
    ]
    external_packages = [
        # External
        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf "
                   "go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
        },
        {
            "name": ["gowitness"],
            "command": "multiple",
            "cmd": "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin",
        },
        {
            "name": [
                "getallurls",
                "httpx-toolkit",
                "assetfinder",
                "brutespray",
                "subfinder",
            ],
            "command": "sudo apt install",
        },
        {
            "name": ["urlhunter"],
            "command": "multiple",
            "cmd": "go install -v github.com/utkusen/urlhunter@latest &&  sudo cp ~/go/bin/urlhunter /usr/bin",
        },
        {
            "name": ["chad"],
            "command": "multiple",
            "cmd": "pipx install google-chad && pipx install --upgrade google-chad && playwright install chromium",
        },
        {"name": ["bbot"], "command": "pipx install"},
        {
            "name": ["python3-dnspython", "python3-urllib3", "python3-bs4"],
            "command": "sudo apt install",
        },
        {
            "name": ["snallygaster"],
            "command": "pipx install snallygaster ",
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
        {
            "name": ["pipx"],
            "command": "multiple",
            "cmd": "sudo apt install pipx git && pipx ensurepath",
        }
    ]
    mobile_packages = [
        # Mobile
        # Install on Device
        # 1. WiFi ADB
        # 2. Magisk Frida / SQlite
        # 3. Drozer
        {
            "name": ["apktool"],
            "command": "multiple",
            "cmd": "sudo apt -y install aapt \
                wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool \
                chmod +x apktool && cp apktool /usr/local/bin/apktool \
                wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar \
                chmod +x apktool.jar && cp apktool.jar /usr/local/bin/apktool.jar",
        },
        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf "
                   "go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
        },
        {
            "name": [
                "adb",
                "d2j-dex2jar",
                "nuclei",
                "radare2",
                # "libusbmuxd-tools",
                "sqlite3",
                "sqlitebrowser",
                "xmlstarlet",
                "apksigner",
                "zipalign",
                "pkg-config",
                "checkinstall",
                "git",
                "autoconf",
                "automake",
                "usbmuxd",
            ],
            "command": "sudo apt-get -y install ",
        },
        {
            "name": ["objection", "file-scraper"],  # "frida-tools",
            "command": "pipx install",
        },
        {"name": ["java"], "command": "sudo apt install default-jdk -y"},
        {
            "name": ["property-lister"],
            "command": "pipx install --upgrade ",
        },
        {"name": ["plistutil"], "command": "apt-get -y install "},
    ]
    nessus_headers = [
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
    rapid7_headers = [
        "Vulnerability Title",
        "Asset Alternate IPv4 Addresses",
        "Asset IP Address",
        "Asset MAC Addresses",
        "Asset Names",
        "Custom Tag",
        "Asset OS Family",
        "Asset OS Name",
        "Asset OS Version",
        "Exploit Count",
        "Exploit URLs",
        "Malware Kit Count",
        "Exploit Minimum Skill",
        "Asset Risk Score",
        "Service Name",
        "Service Port",
        "Vulnerability Severity Level",
        "Vulnerability CVE IDs",
        "Vulnerability CVSS Score",
        "Vulnerability CVE URLs",
        "Vulnerability Description",
        "Vulnerability Solution",
        "Vulnerability Risk Score",
        "Vulnerability PCI Compliance Status",
        "Vulnerable Since",
    ]
    column_mismatch_error = (
        f"{Bcolors.FAIL}{Bcolors.BOLD}[!]Column mismatch between files. Ensure all files have the "
        f"same number of columns {Bcolors.ENDC}"
    )

    @staticmethod
    def filter_conditions(vulnerabilities, regex_word, filter_param):
        match filter_param:
            case "ssl_condition":
                return {
                    "ssl_condition": (vulnerabilities["Name"].notna())
                                     & (
                                         vulnerabilities["Name"].str.contains(
                                             regex_word("SSL"), regex=True
                                         )
                                     )
                                     | (
                                         vulnerabilities["Name"].str.contains(
                                             regex_word("TLS"), regex=True
                                         )
                                     )
                                     | (
                                         vulnerabilities["Name"].str.contains(
                                             regex_word("POODLE"), regex=True
                                         )
                                     )
                }
            case "missing_patch_condition":
                return {
                    "missing_patch_condition": (vulnerabilities["Solution"].notna())
                                               & (
                                                   vulnerabilities["Solution"].str.contains(
                                                       regex_word("Update"), regex=True
                                                   )
                                               )
                                               | (vulnerabilities["Solution"].str.contains(regex_word("patches")))
                                               | (vulnerabilities["Solution"].str.contains(regex_word("updates")))
                                               | (
                                                   vulnerabilities["Solution"].str.contains(
                                                       regex_word("security update")
                                                   )
                                               )
                                               | (
                                                   vulnerabilities["Solution"].str.contains(
                                                       regex_word("Microsoft has released")
                                                   )
                                               ),
                }
            case "unsupported_software":
                return {
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
                }
            case "kaspersky_condition":
                return {
                    "kaspersky_condition": (vulnerabilities["Name"].notna())
                                           & vulnerabilities["Name"].str.contains(
                        regex_word("Kaspersky"), regex=True
                    ),
                }
            case "insecure_condition":
                return {
                    "insecure_condition": (vulnerabilities["Name"].notna())
                                          & vulnerabilities["Name"].str.contains(
                        regex_word("Insecure Windows Service"), regex=True
                    ),
                }
            case "winverify_condition":
                return {
                    "winverify_condition": (vulnerabilities["Name"].notna())
                                           & vulnerabilities["Name"].str.contains(
                        regex_word("WinVerifyTrust"), regex=True
                    ),
                }
            case "unquoted_condition":
                return {
                    "unquoted_condition": (vulnerabilities["Name"].notna())
                                          & vulnerabilities["Name"].str.contains(
                        regex_word("Unquoted Service Path"), regex=True
                    ),
                }
            case "smb_condition":
                return {
                    "smb_condition": (vulnerabilities["Name"].notna())
                                     & vulnerabilities["Name"].str.contains(
                        regex_word("SMB"), regex=True
                    ),
                }
            case "speculative_condition":
                return {
                    "speculative_condition": (vulnerabilities["Name"].notna())
                                             & vulnerabilities["Name"].str.contains(
                        regex_word("Windows Speculative"), regex=True
                    ),
                }
            case "AD_condition":
                return {
                    "AD_condition": (vulnerabilities["Name"].notna())
                                    & vulnerabilities["Name"].str.contains(
                        regex_word("AD Starter"), regex=True
                    ),
                }
            case "defender_condition":
                return {
                    "defender_condition": (vulnerabilities["Synopsis"].notna())
                                          & vulnerabilities["Synopsis"].str.contains(
                        regex_word("antimalware"), regex=True
                    ),
                }
            case "rdp_condition":
                return {
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
                }
            case "compliance_condition":
                return {
                    "compliance_condition": (vulnerabilities["Risk"].notna())
                                            & (
                                                vulnerabilities["Risk"].str.contains(
                                                    regex_word("FAILED"), regex=True
                                                )
                                            )
                                            & (
                                                vulnerabilities["Synopsis"].str.contains(
                                                    regex_word("Compliance checks"), regex=True
                                                )
                                            ),
                }
            case "ssh_condition":
                return {
                    "ssh_condition": (vulnerabilities["Synopsis"].notna())
                                     & vulnerabilities["Synopsis"].str.contains(
                        regex_word("SSH server"), regex=True
                    ),
                }
            case "telnet_condition":
                return {
                    "telnet_condition": (vulnerabilities["Name"].notna())
                                        & vulnerabilities["Name"].str.contains(
                        regex_word("Telnet Server"), regex=True
                    ),
                }
            case "information_condition":
                return {
                    "information_condition": (vulnerabilities["Name"].notna())
                                             & vulnerabilities["Name"].str.contains(
                        regex_word("Information Disclosure"), regex=True
                    ),
                }
            case "web_condition":
                return {
                    "web_condition": (vulnerabilities["Name"].notna())
                                     & (
                                         vulnerabilities["Name"].str.contains(
                                             regex_word("Web"), regex=True
                                         )
                                     )
                                     | (
                                         vulnerabilities["Description"].str.contains(
                                             regex_word("web server"), regex=True
                                         )
                                     ),
                }
            case "rce_condition":
                return {
                    "rce_condition": (vulnerabilities["Description"].notna())
                                     & (
                                         vulnerabilities["Description"].str.contains(
                                             regex_word("remote code execution"), regex=True
                                         )
                                     ),
                }
            case _:
                pass

    nessus_strings_to_filter = [
        "ssl_condition",
        "missing_patch_condition",
        "unsupported_software",
        "kaspersky_condition",
        "insecure_condition",
        "winverify_condition",
        "unquoted_condition",
        "smb_condition",
        "speculative_condition",
        "AD_condition",
        "defender_condition",
        "rdp_condition",
        "compliance_condition",
        "ssh_condition",
        "telnet_condition",
        "information_condition",
        "web_condition",
        "rce_condition",
    ]
    nessus_vuln_categories = {
        "ssl_issues": "ssl_condition",
        "missing_patches": "missing_patch_condition",
        "unsupported": "unsupported_software",
        "kaspersky": "kaspersky_condition",
        "insecure_service": "insecure_condition",
        "winverify": "winverify_condition",
        "unquoted": "unquoted_condition",
        "smb_issues": "smb_condition",
        "speculative": "speculative_condition",
        "active_directory": "AD_condition",
        "defender": "defender_condition",
        "rdp_misconfig": "rdp_condition",
        "compliance": "compliance_condition",
        "ssh_misconfig": "ssh_condition",
        "telnet": "telnet_condition",
        "information_disclosure": "information_condition",
        "web_issues": "web_condition",
    }
    rapid7_strings_to_filter = []
    rapid7_vuln_categories = {}

    # MOBILE ANALYSIS CONSTANTS
    # Define regex patterns as raw strings for better readability and handling
    IOS_FILE_SEARCH = r"hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView"
    BEARER_REGEX = r"[^\w\d]+(basic|bearer)\s.+"
    HARDCODED_REGEX = (
        r"(\?access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key"
        r"|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer"
        r'|user)\w*(?:"\s*:\s*|\s*=).+'
    )
    HARDCODED_REGEX_2 = r"([^\w\d]+(to(_|\s)do|todo|note)\s|//|/\*|\*/).+"
    BASE64_REGEX = r"(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}=|[a-zA-Z0-9\+\/]{2}==)"
    IP_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    URL_REGEX = r"\w+://[\w\-\.\@\:\/\?\=\%\&\#]+"
    DEEPLINKS_IGNORE_REGEX = r"\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)"
