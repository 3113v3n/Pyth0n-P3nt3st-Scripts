
import sys
from utils.shared import Bcolors
from argparse import ArgumentParser, Action


class CustomArgumentParser(ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(
            f"\n{Bcolors.FAIL}[!]Error:{Bcolors.ENDC} {message}\n")
        sys.exit(2)


class CustomHelp(Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)
        self.color = Bcolors

    def __call__(self, parser, namespace, values, option_string=None):
        simple_help_text = (f"""{self.color.HEADER}=== Custom Help Menu ==={self.color.ENDC}
This is a custom CLI tool for Penetration Testing.
              
{self.color.BOLD}Usage:{self.color.ENDC}
               {self.color.ITALICS}main.py -M <interactive|cli_args [MODULES..] [OPTIONS..]> {self.color.ENDC}
                
{self.color.BOLD}Options:{self.color.ENDC}
    -M MODE   Select mode: 'interactive' or 'cli_args'
              {self.color.OKGREEN}interactive:{self.color.ENDC} Run with user interaction
              {self.color.OKGREEN}cli_args:{self.color.ENDC}    Run with command-line arguments
        
{self.color.BOLD}MODULE:{self.color.ENDC}       Choose module:                          mobile, internal, password, va, external
                   internal:                          Handle Internal Penetration Testing
                   mobile  :                          Handle Mobile Penetration Testing
                   password:                          Handle Password-related operations
                   va      :                          Handle Vulnerability Analysis
                   external:                          Handle External Penetration Testing
{self.color.BOLD}OPTIONS:{self.color.ENDC}      Module-specific options

""")
        more_text = (f"""
    {self.color.OKCYAN}[internal]{self.color.ENDC} 
        -a, --action            <action>            : Choose action to perform : scan, resume

            <scan>
                -o, --output    <output_file>       : Output file for scan results
                --ip            <ip/subnet>         : Ip address to scan
            <resume>
                -r, --resume_file    <unresponsive_file> : File with unresponsive hosts
                -m, --mask      <mask>              : Subnet mask used for previous scan
        -I, --interface         <network_interface> : The network interface to use on the scan

    {self.color.OKCYAN}[mobile]{self.color.ENDC}
        -P, --path              <apk_ipa_file>      : Path to the mobile application file
                                                     <apk | ipa>

    {self.color.OKCYAN}[password]{self.color.ENDC}
        -t, --test                                  : Test the password against a protocol
            [{self.color.ITALICS}ip | domain | pass_file{self.color.ENDC}]

            -d, --domain        <domain>            : Domain to test
            -p, --pass_file     <pass_file>         : Password file to test
            --ip                <target_ip>         : Target IP address

        -g, --generate                              : Generate a password list from cracked hashes
            [{self.color.ITALICS}crack | output | dump{self.color.ENDC}]

            -c, --crack         <cracked_hashes>    : File with Cracked hashes
            -o, --output        <output_file>       : Output file
            --dump              <dump_file>         : NTDS Dump file

    {self.color.OKCYAN}[vulnerability analysis]{self.color.ENDC}
        -s, --scanner           <scanner>           : Scanner used for analysis e.g( nessus | rapid )
        -o, --output            <output_file>       : Output file for your Vulnerability analysis report
        -P, --path              <path_to_files>     : Path to your scanned files

    {self.color.OKCYAN}[external]{self.color.ENDC}
        -d, --domain            <domain>            : Domain to test

{self.color.BOLD}EXAMPLES:{self.color.ENDC}==> 
        [{self.color.OKGREEN}Run script interactively{self.color.ENDC}]
        main.py -M interactive 

        [{self.color.OKGREEN}Run script with command line arguments{self.color.ENDC}]
        1.{self.color.WARNING}Mobile:{self.color.ENDC}
                main.py -M cli_args mobile -P /path/to/app.apk
        
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
        
 -h, --help  Show this custom help""")
        # Check if verbose flag is set in namespace
        # print(namespace)

        full_help_text = simple_help_text + more_text
        print(full_help_text)
        sys.exit(0)
