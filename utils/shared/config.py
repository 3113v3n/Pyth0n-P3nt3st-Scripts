import re

from .configurations import (
    MobileConfigs,
    ExternalConfigs,
    VAConfigs,
    InternalConfigs)


class Config(
        InternalConfigs,
        VAConfigs,
        MobileConfigs,
        ExternalConfigs):
    def __init__(self):
        super().__init__()
        self.SUMMARY_HELPER_TEXT=F"""[Author: 3113v3n]
        {self.color.HEADER}=== Custom Help Menu ==={self.color.ENDC}
This is a custom CLI tool for Penetration Testing.

              
{self.color.BOLD}Usage:{self.color.ENDC}
               {self.color.ITALICS}main.py -M [ <interactive>|<cli_args [MODULES..] [OPTIONS..]> ] {self.color.ENDC}
                
{self.color.BOLD}Options:{self.color.ENDC}
    -M MODE   Select mode: 'interactive' or 'cli_args'
              {self.color.OKGREEN}interactive:{self.color.ENDC} Run with user interaction
              {self.color.OKGREEN}cli_args:{self.color.ENDC}    Run with command-line arguments
        
{self.color.BOLD}MODULE:{self.color.ENDC}       Choose module:                          [mobile, internal, password, va, external]

                   internal:                          Handle Internal Penetration Testing
                   mobile  :                          Handle Mobile Penetration Testing
                   password:                          Handle Password-related operations
                   va      :                          Handle Vulnerability Analysis
                   external:                          Handle External Penetration Testing
{self.color.BOLD}OPTIONS:{self.color.ENDC}      Module-specific options

"""
        self.EXTRA_HELPER_TEXT=f"""
    {self.color.OKCYAN}[internal]{self.color.ENDC} 
        -a, --action                 ACTION             : Choose action to perform : scan, resume

            <scan>
                -o, --output         FILE               : Output file for scan results
                --ip                 IP_CIDR            : Ip address to scan in format (10.0.0.0/24)
            <resume>
                -r, --resume_file    FILE               : File with unresponsive hosts
                -m, --mask           MASK               : Subnet mask used for previous scan
        -I, --interface              INTERFACE          : The network interface to use on the scan (eth0,wlan0)

    {self.color.OKCYAN}[mobile]{self.color.ENDC}
        -P, --path                   FILE/FOLDER        : Path to mobile app file (apk|ipa) or directory with apps
            --scan-mode              MODE               : Directory handling mode in cli_args [single|all] (default: all)

    {self.color.OKCYAN}[password]{self.color.ENDC}
        -t, --test                                      : Test the password against a protocol
            [{self.color.ITALICS}ip | domain | pass_file{self.color.ENDC}]

            -d, --domain             DOMAIN             : Domain to test
            -p, --pass_file          PASSLIST           : Password file to test
            --ip                     TARGET             : Target IP address

        -g, --generate                                  : Generate a password list from cracked hashes
            [{self.color.ITALICS}crack | output | dump{self.color.ENDC}]

            -c, --crack              HASHES             : File with Cracked hashes
            -o, --output             FILE               : Output file
            --dump                   DUMPS              : NTDS Dump file

    {self.color.OKCYAN}[vulnerability analysis]{self.color.ENDC}
        -s, --scanner               SCANNER             : Scanner used for analysis e.g( nessus | rapid )
        -o, --output                FILE                : Output file for your Vulnerability analysis report
        -P, --path                  FOLDER              : Path to your scanned files

    {self.color.OKCYAN}[external]{self.color.ENDC}
        -d, --domain                DOMAIN              : Domain to test

{self.color.BOLD}EXAMPLES:{self.color.ENDC}==> 
        [{self.color.OKGREEN}Run script interactively{self.color.ENDC}]
        main.py -M interactive 

        [{self.color.OKGREEN}Run script with command line arguments{self.color.ENDC}]
        1.{self.color.WARNING}Mobile:{self.color.ENDC}
                main.py -M cli_args mobile -P /path/to/app.apk
                main.py -M cli_args mobile -P /path/to/apps --scan-mode all
        
        2.{self.color.WARNING}Internal:{self.color.ENDC}
            Scan:
                main.py -M cli_args internal -a scan  -I eth0 --ip 10.10.10.2/24 -o scan_results.txt
            Resume:
                main.py -M cli_args internal -a resume -I eth0  -r unresponsive_hosts.txt -m 24
        
        3.{self.color.WARNING}Password:{self.color.ENDC}
            test:
                main.py -M cli_args password -t -d domain.example.com -p /path/to/pass-file --ip 192.168.1.1
            generate:
                main.py -M cli_args password -g -c /path/to/crack-file -o output.txt --dump /path/to/dump-file
        
        4.{self.color.WARNING}Vulnerability Analysis:{self.color.ENDC}
                main.py -M cli_args va -s nessus -o report.txt -P /path/to/scanned-files
        
 -h, --help  Show this custom help"""
        self.PROGRAM_HELPER_STRING = self.SUMMARY_HELPER_TEXT + self.EXTRA_HELPER_TEXT

    # Reusable API key checklist constants (shared across modules).
    GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
    GOOGLE_API_TEST_ENDPOINTS: tuple[tuple[str, str], ...] = (
        (
            "maps_geocoding",
            "https://maps.googleapis.com/maps/api/geocode/json?address=Paris&key={key}",
        ),
        (
            "youtube_data",
            "https://www.googleapis.com/youtube/v3/videos?part=id&id=dQw4w9WgXcQ&key={key}",
        ),
    )
    GOOGLE_RESTRICTION_MARKERS: tuple[str, ...] = (
        "not authorized to use this api key",
        "api keys with referer restrictions",
        "requests from referer",
        "this ip, site or mobile application is not authorized",
        "android apps package name and sha-1 certificate fingerprint",
        "ios apps bundle identifier",
    )

    API_KEY_VALUE_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
        ("Google API Key", GOOGLE_API_KEY_RE),
        ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("Stripe Live Key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
        ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    )
    GENERIC_API_KEY_ASSIGNMENT_RE = re.compile(
        r"(?i)\bapi[_-]?key\b\s*(?:[:=]|=>)\s*[\"']([^\"'\n]{8,})[\"']"
    )

    API_KEY_CHECKLIST: tuple[dict[str, str], ...] = (
        {
            "id": "hardcoded-key-exposure",
            "cwe": "CWE-798",
            "cve": "N/A",
            "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        },
        {
            "id": "restriction-controls",
            "cwe": "CWE-284",
            "cve": "N/A",
            "cvss": "8.2 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L)",
        },
        {
            "id": "least-privilege-api-scope",
            "cwe": "CWE-285",
            "cve": "N/A",
            "cvss": "7.4 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)",
        },
        {
            "id": "quota-and-billing-abuse",
            "cwe": "CWE-770",
            "cve": "N/A",
            "cvss": "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)",
        },
    )

    @staticmethod
    def clean_line(text: str, max_len: int = 220) -> str:
        text = " ".join(str(text).strip().split())
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    @staticmethod
    def mask_secret(secret: str, keep: int = 4) -> str:
        if len(secret) <= keep * 2:
            return "*" * len(secret)
        return f"{secret[:keep]}...{secret[-keep:]}"

    @staticmethod
    def extract_google_error(payload: dict, fallback: str = "") -> str:
        if not isinstance(payload, dict):
            return fallback

        if payload.get("error_message"):
            return str(payload["error_message"])

        error_obj = payload.get("error")
        if isinstance(error_obj, dict) and error_obj.get("message"):
            return str(error_obj.get("message"))

        status = payload.get("status")
        if isinstance(status, str) and status not in {"OK", "ZERO_RESULTS"}:
            return status
        return fallback
    domain_select_error = ("\n[!] Please choose one of: \n")

    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing", "alias": "internal", "icon": "🖥️"},
        {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
        {"domain": "Vulnerability Analysis", "alias": "va", "icon": "🔎"},
        {"domain": "Password Module", "alias": "password", "icon": "🔐"},
        {"domain": "Exit Program", "alias": "exit", "icon": "✖"}
    ]
    scan_modes = ["SCAN", "RESUME"]

    vulnerability_scanners = [
        {"name": "Nessus Scanner", "alias": "nessus"},
        {"name": "Rapid7 Scanner", "alias": "rapid"},
    ]

    general_packages = [
        {
            "name": ["pipx"],
            "command": "multiple",
            "cmd": "sudo apt-get -y install pipx git && pipx ensurepath",
        },
        {
            "name": ["anthropic"],
            "command": "multiple",
            "cmd": "python -m pip install anthropic",
        }
    ]
