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
