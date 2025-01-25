from .configurations import VAConfigs, MobileConfigs, ExternalConfigs, InternalConfigs


class Config(VAConfigs, MobileConfigs, ExternalConfigs, InternalConfigs):
    def __init__(self):
        super().__init__()
        self.domain_select_error = (f"\n{self.FAIL}[!]"
                                    f"{self.ENDC} Please choose one of: \n")

    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing",
            "alias": "internal", "icon": "🖥️"},
        # {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
        {"domain": "Vulnerability Analysis", "alias": "va", "icon": "🔎"},
        {"domain": "Exit Program", "alias": "exit", "icon": ""},
    ]
    scan_modes = ["SCAN", "RESUME"]

    vulnerability_scanners = [
        {"name": "Nessus Scanner", "alias": "nessus"},
        {"name": "Insight VM", "alias": "rapid"},
    ]

    general_packages = [
        {
            "name": ["pipx"],
            "command": "multiple",
            "cmd": "sudo apt install pipx git && pipx ensurepath",
        }
    ]