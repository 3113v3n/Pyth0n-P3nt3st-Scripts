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
        self.INTERACTIVE_HELPER_STRING = F"""{self.HEADLINE}
 Usage: script_name.py [ --(interactive | arguments | help) ] 

    Args:
        --interactive: Run the script in interactive mode.
        --arguments: Run the script with arguments.
        --help: Show this help message and exit.

    [arguments]:
        Run script with arguments.(one liner)
        Usage: script_name.py --arguments  [OPTIONS] [Flags] 

        [OPTIONS]: Options for the script. (mobile|internal|password|va|external)
                mobile :    Handle mobile assessment
                internal:   Handle internal PT
                password:   Perform password related operation
                va:         Handle vulnerability assessment
                external    Handle External PT

        [Flags]: Flags for the script .
                
                <mobile>
                    (-P | --path) <path> : Path to the mobile assessment file.

                Example:
                    script_name.py --arguments mobile -P /path/to/file

                <internal>
                    (-M | --mode) <mode> : Mode of the internal PT (e.g., 'scan', 'resume').
                    
                    <scan>
                        (-ip )          <ip> : Target IP address with subnet for the scan. [10.1.1.1/24]
                        (-o | --output) <output> : Output file for the scan results.

                    <resume>
                        (-r | --resume)  <resume_file> : File with the unresponsive hosts.
                        (-m | --mask)   <mask> : Subnet mask used for previous scan [0-32].  

                Example:
                    script_name.py -M scan -ip 10.10.1.2/24 -o Test_scan_file
                    script_name.py --mode resume -r /path/to/Test_scan_file_unresponsive -m 24                 

                <password>
                    (-t | --test)                        : Test the password against a protocol.
                    <test> 
                        (-ip)               <ip>         : Target IP address.
                        (-d | --domain)     <domain>     : Domain name.
                        (-p | --pass_file)  <pass_file>  : Password file.
                        
                    (-g | --generate) : Generate a password list from cracked hashes.
                    <generate>
                        (-c | --crack)  <crack_file> : File with cracked hashes.
                        (-o | --output) <output_file> : Output file for the generated password list.
                        (--dump)        <dumps> : NTDS dump file.

                Example:
                    script_name.py -t -ip 0.0.0.0 -d domain.local -p pass_file.txt
                    script_name.py --generate -c cracked_hashes.txt -o password_list.txt --dump dumps.ntds

                <va>
                    (-s |--scanner) <scanner>: Specify the scanner used for vulnerability assessment (nessus|rapid).
                    (-ext | --extension) <extension>: Specify the file extension for the vulnerability assessment scans
                                            (e.g., csv, xslx, xlx or both).
                    (-o | --output) <output>: Specify the output file for the vulnerability assessment report.
                    (-P | --path )  <file path> : Path to your scanned files
                
                Example:
                    script_name.py --scanner nessus -ext csv -o report_name -P /path/to/scanned_files
                    script_name.py --scanner rapid -ext xslx -o report_name -P /path/to/scanned_files
                    script_name.py --scanner nessus -ext both -o report_name -P /path/to/scanned_files

                    
                <external>

                --help: Show help message for individual module and exit.
                --DEBUG: Enable debug mode.
                --quiet: Suppress output.
   

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
