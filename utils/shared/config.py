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
        pass
    domain_select_error = ("\n[!] Please choose one of: \n")

    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing","alias": "internal", "icon": "🖥️"},
        # {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
        {"domain": "Vulnerability Analysis", "alias": "va", "icon": "🔎"},
        {"domain": "Password Module", "alias":"password", "icon":"🔐"},
        {"domain": "Exit Program", "alias": "exit", "icon": "✖"},
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
            "cmd": "sudo apt install pipx git && pipx ensurepath",
        }
    ]
