from ..colors import Bcolors


class VAConfigs:
    def __init__(self):
        pass

    NESSUS_HEADERS = [
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
    SUMMARY_SHEET_HEADERS = [
        "S.No",
        "Observation",
        "Description",
        "Impact",
        "Risk Rating",
        "Recommendation",
        "Affected Hosts",
        "Management Response",
    ]

    RAPID7_HEADERS = [
        "Vulnerability Title",
        "Asset Names",
        "Custom Tag",
        "Asset IP Address",
        "Asset Alternate IPv4 Addresses",
        "Asset OS Name",
        "Asset OS Family",
        "Service Name",
        "Asset OS Version",
        "Service Port",
        "Vulnerability Description",
        "Vulnerability CVE IDs",
        "Vulnerability CVSS Score",
        "Vulnerability Solution",
        "Exploit Count",
        "Exploit URLs",
        "Malware Kit Count",
        "Exploit Minimum Skill",
        "Asset Risk Score",
        "Asset MAC Addresses",
        "Vulnerability Severity Level",
        "Vulnerability CVE URLs",
        "Vulnerability Risk Score",
        "Vulnerability PCI Compliance Status",
        "Vulnerable Since",
    ]

    column_mismatch_error = (
        f"{Bcolors.FAIL}{Bcolors.BOLD}[!]Column mismatch between files. "
        f" Ensure all files have the same number of columns {Bcolors.ENDC}"
    )
    # TODO: combine strings and categories
    NESSUS_STRINGS_TO_FILTER = [
        "ssl_condition",
        "missing_patch_condition",
        "unsupported_software_condition",
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
        "reboot_condition",
    ]
    NESSUS_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software_condition",
        "Kaspersky": "kaspersky_condition",
        "Insecure Service": "insecure_condition",
        "Winverify": "winverify_condition",
        "Unquoted Service Path": "unquoted_condition",
        "SMB Issues": "smb_condition",
        "Windows Speculative": "speculative_condition",
        "Active Directory": "AD_condition",
        "Windows Defender": "defender_condition",
        "RDP Misconfig": "rdp_condition",
        "Compliance": "compliance_condition",
        "SSH Misconfig": "ssh_condition",
        "Telnet": "telnet_condition",
        "Information Disclosure": "information_condition",
        "Web Application Issues": "web_condition",
        "Windows Update Reboot": "reboot_condition",
    }
    # strings and categories need to be same number
    RAPID7_STRINGS_TO_FILTER = [
        "ssl_condition",
        "missing_patch_condition",
        "unsupported_software_condition",
        "web_condition",
        "compliance_condition",
        "ssh_condition",
        "database_condition",
    ]
    RAPID7_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software_condition",
        "SSH Misconfig": "ssh_condition",
        "Database Misconfigurations": "database_condition",
        "Web Application Issues": "web_condition",
        "Compliance": "compliance_condition",
    }
    SCAN_FILE_FORMAT = ("csv", "xlsx", "both")
    SSL_FILTER_STRINGS ="SSL|TLS|POODLE|Diffie-Hellman"
    PATCH_FILTER_STRINGS = "patches|updates|security update|Microsoft has released|Update|update"
    UPGRADE_FILTER_STRINGS = (
        "no longer supported|unsupported|Unsupported Version|Obsolete Version|end-of-life|Upgrade|upgrade|discontinued"
    )
    REBOOT_FILTER_STRINGS = "reboot|Reboot"
    RDP_FILTER_STRINGS = "Terminal Services|Remote Desktop Protocol"
    WEB_FILTER_STRINGS = "Web|web server|HTTP|HSTS|HTTPS|IIS"
    UNIVERSAL_IGNORE_FILTER = "Upgrade|Update|upgrade|update|patch"
    WEB_IGNORE_FILTER = "TLS|SSL"

    # Scanner-specific column mappings
    COLUMNS = {
        'nessus': {
            'title': 'Name',
            'solution': 'Solution',
            'description': 'Description',
            'synopsis': 'Synopsis',
            'risk': 'Risk'
        },
        'rapid': {
            'title': 'Vulnerability Title',
            'solution': 'Vulnerability Solution',
            'service': 'Service Name',
            'pci_status': 'Vulnerability PCI Compliance Status'
        }
    }