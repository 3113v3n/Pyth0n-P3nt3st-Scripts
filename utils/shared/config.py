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
        self.PROGRAM_HELPER_STRING = F"""{self.HEADLINE}
        [ Author: 3113v3n ]
    This program is meant to help in automating some common penetration
     steps accross various domain 
     [internal | mobile | external | password| Vulnerability Analysis]

     {self.color.HEADER}{self.color.UNDERLINE}Domains{self.color.ENDC}:

            [{self.color.OKGREEN}Internal{self.color.ENDC}]   
                                        This module has 2 modes [scan | resume]
                                        {self.color.WARNING}Scan mode{self.color.ENDC}:
                                        Allows starting a fresh scan and requires an 
                                         IP address and subnet mask (10.10.1.2/16)

                                        {self.color.WARNING}Resume mode{self.color.ENDC}:
                                        This mode resumes a previously initated scan and 
                                        updates the original list with new IPs.

        ------------------------------------------------------------------------------------
            [{self.color.OKGREEN}Mobile{self.color.ENDC}]                    This module does static analysis on an apk / iOS file
                                         and generates files with potential crucial information

        ------------------------------------------------------------------------------------
            [{self.color.OKGREEN}Password{self.color.ENDC}]                  This module assists with password related operations
                                          such as: 
                                              - generating password list from dumps
                                              - testing passwords on network target

        -------------------------------------------------------------------------------------    
            [{self.color.OKGREEN}External{self.color.ENDC}]                  [This module is still work in progress]
            
        -------------------------------------------------------------------------------------
            [{self.color.OKGREEN}Vulnerability Analysis{self.color.ENDC}]    This module automates the process of analyzing result
                                         scans generated from Nessus and Insight VM tool
{self.HEADLINE}"""

    domain_select_error = ("\n[!] Please choose one of: \n")

    test_domains = [
        {"domain": "Mobile   Penetration Testing", "alias": "mobile", "icon": "📱"},
        {"domain": "Internal Penetration Testing",
            "alias": "internal", "icon": "🖥️"},
        # {"domain": "External Penetration Testing", "alias": "external", "icon": "🌐"},
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
            "cmd": "sudo apt install pipx git && pipx ensurepath",
        }
    ]
