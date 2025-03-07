from ..colors import Bcolors


class VAConfigs:
    color = Bcolors

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
        "ssh_condition",
        "telnet_condition",
        "information_condition",
        "web_condition",
        "rce_condition",
        "reboot_condition",
        "compliance_condition",
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
        "SSH Misconfig": "ssh_condition",
        "Telnet": "telnet_condition",
        "Remote Code Execution": "rce_condition",
        "Information Disclosure": "information_condition",
        "Web Application Issues": "web_condition",
        "Windows Update Reboot": "reboot_condition",
        "Compliance": "compliance_condition",
    }
    # strings and categories need to be same number
    RAPID7_STRINGS_TO_FILTER = [
        "ssl_condition",
        "missing_patch_condition",
        "unsupported_software_condition",
        "web_condition",
        "ssh_condition",
        "database_condition",
        "compliance_condition",
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
    SSL_FILTER_STRINGS = "SSL|TLS|POODLE|Diffie-Hellman"
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
    HEADLINE = f"\n{color.HEADER}[*]INFO[*]{color.ENDC}\n"
    VULNERABILITY_HELPER_STRING = f"""{HEADLINE}
    Runs Vulnerability analysis on scans generated by Nessus or Rapid7

    Ensure the scan results have {color.BOLD}all column headers of equal number{color.ENDC} to avoid
    errors.
    For Nessus, the scan filters out only {color.UNDERLINE}{color.BOLD}Credentialed{color.ENDC} scans
    
    {color.HEADER}{color.UNDERLINE}required arguments{color.ENDC}:

            {color.OKGREEN}scan_folder{color.ENDC}      File Path to your scan results
            {color.OKGREEN}scanner{color.ENDC}          The scanner used [ {color.WARNING}Nessus | Rapid7{color.ENDC} ]
            {color.OKGREEN}file_type{color.ENDC}        The output filetype [ {color.WARNING}CSV | XLSX | Both{color.ENDC} ]
            {color.OKGREEN}filename{color.ENDC}         The name of your output file

    {color.HEADER}{color.UNDERLINE}return{color.ENDC}:
            {color.OKGREEN}filtered_list{color.ENDC}    Output file with the filtered vulnerabilities
            {color.OKGREEN}unfiltered_list{color.ENDC}  File containing list of all vulnerabilities that
                              were not analzed, for manual input
{HEADLINE}"""
