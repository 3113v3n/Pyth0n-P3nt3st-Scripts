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
        "Management Response"
    ]
    
    RAPID7_HEADERS  = [
        "Vulnerability Title",
        "Asset Names",
        "Asset IP Address",
        "Asset OS Name",
        "Service Name",
        "Service Port",
        "Vulnerability Description",
        "Vulnerability Solution",
        "Vulnerability CVSS Score",
        "Asset MAC Addresses",
        "Custom Tag",
        "Asset OS Family",
        "Asset OS Version",
        "Exploit Count",
        "Exploit URLs",
        "Malware Kit Count",
        "Exploit Minimum Skill",
        "Asset Risk Score",
        "Vulnerability Severity Level",
        "Vulnerability CVE IDs",
        "Vulnerability CVE URLs",
        "Vulnerability Risk Score",
        "Vulnerability PCI Compliance Status",
        "Vulnerable Since",
        "Asset Alternate IPv4 Addresses",
    ]
    
    column_mismatch_error = (
        f"{Bcolors.FAIL}{Bcolors.BOLD}[!]Column mismatch between files. "
        f" Ensure all files have the same number of columns {Bcolors.ENDC}"
    )
    NESSUS_STRINGS_TO_FILTER = [
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
    NESSUS_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software",
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
    }
    # strings and categories need to be same number
    RAPID7_STRINGS_TO_FILTER = ["ssl_condition", "missing_patch_condition",
                                "unsupported_software", "web_condition",
                                "compliance_condition", "ssh_condition", ]
    RAPID7_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software",
        "SSH Misconfig": "ssh_condition",
        "Web Application Issues": "web_condition",
        "Compliance": "compliance_condition",
    }
    SCAN_FILE_FORMAT = ("csv", "xlsx", "both")
