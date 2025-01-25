from ..colors import Bcolors


class VAConfigs():
    def __init__(self):
        pass
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
        f"{Bcolors.FAIL}{
            Bcolors.BOLD}[!]Column mismatch between files. Ensure all files have the "
        f"same number of columns {Bcolors.ENDC}"
    )
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
