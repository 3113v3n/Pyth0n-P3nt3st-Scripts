from ..colors import Bcolors


class InternalConfigs:
    colors = Bcolors
    internal_packages = [
        # Internal
        {
            "name": ["netexec"],
            "command": "multiple",
            "cmd": " pipx install git+https://github.com/Pennyw0rth/NetExec",
        },
        {
            "name": ["exiftool"],
            "command": "sudo apt-get -y install libimage-exiftool-perl",
        },
    ]

    internal_mode_choice = (
        f"\n[+] Select scan mode: [{colors.OKCYAN}SCAN | RESUME{colors.ENDC}]"
        f"\n\n{colors.OKCYAN}SCAN{colors.ENDC}: Scan a new subnet."
        f"\n{colors.WARNING}RESUME{colors.ENDC}: Continue a previous scan. "
        "\n\n Enter mode: ==> "
    )

    internal_choice_error = (
        f"\n{colors.FAIL}[!]{colors.ENDC} Please select one of: [ {
            colors.OKCYAN}SCAN | RESUME"
        f"{colors.ENDC} ]"
        "\n\n Enter mode: ==> "
    )
    HEADLINE = f"\n{colors.HEADER}[*]INFO[*]{colors.ENDC}\n"
    HASH_HELPER_STRING = f"""{HEADLINE}
        Compares your cracked hashes to your dumped hashes and creates a password
        file that has all the username and passwords of Enabled users in the AD
        in the following format:

            [{colors.OKGREEN}username{colors.ENDC}]:[{colors.OKGREEN}password{colors.ENDC}]

        Requirement:
            cracked hashes format:
                                 {colors.WARNING}7095e1b8926196214d82f7b6f276{colors.ENDC}:{colors.WARNING}S4mpl3P4ssw0rd!{colors.ENDC}
            dumped hashes format :
                                 {colors.OKCYAN}USERNAME{colors.ENDC}: {colors.OKCYAN}ACCOUNTID{colors.ENDC}: {colors.OKCYAN}NTHASH{colors.ENDC}: {colors.OKCYAN}LMHASH{colors.ENDC}::: {colors.OKCYAN}(ACC STATUS){colors.ENDC}
{HEADLINE}"""

    SCANNER_HELPER_STRING = f"""{HEADLINE}
        Scan your network and enumerate all possible IPs within a subnet
        Select {colors.OKCYAN}{colors.UNDERLINE}Mode{colors.ENDC}:
            {colors.OKGREEN}SCAN{colors.ENDC}     : Start a new scan

                :param:
                    {colors.WARNING}subnet{colors.ENDC}   : Network to scan in format IP/CIDR [{colors.OKBLUE}10.10.1.3/16{colors.ENDC}]
                    {colors.WARNING}filename{colors.ENDC} : Name of file to store your scans

            {colors.OKGREEN}RESUME{colors.ENDC}   : Resume a previous scan 
                       Select the file with your non responsive IPs to resume
                       
                :param:
                    {colors.WARNING}Previous Scan{colors.ENDC}   : Select Previous filename
                    {colors.WARNING}CIDR{colors.ENDC}            : Available in {colors.BOLD}RESUME{colors.ENDC} mode
                                      any value from {colors.BOLD}1 - 32{colors.ENDC}
{HEADLINE}"""
