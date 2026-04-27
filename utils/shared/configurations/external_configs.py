from ..colors import Bcolors


class ExternalConfigs:
    color = Bcolors

    def __init__(self):
        pass

    external_packages = [
        # External
        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "sudo apt-get -y install golang-go",
        },
        {
            "name": ["subjs"],
            "command": "multiple",
            "cmd": "go install github.com/lc/subjs@latest && sudo cp ~/go/bin/subjs /usr/bin"
        },
        {
          "name": ["qsreplace"],
          "command": "multiple",
          "cmd": "go install github.com/tomnomnom/qsreplace@latest && sudo cp ~/go/bin/qsreplace /usr/bin"
        },
        {
            "name": ["gowitness"],
            "command": "multiple",
            "cmd": "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin",
        },
        {
            "name": ["gauplus"],
            "command": "multiple",
            "cmd": "go install github.com/bp0lr/gauplus@latest && sudo cp ~/go/bin/gauplus /usr/bin"
        },
        {
            "name": ["gf", "waybackurls"],
            "command": "multiple",
            "cmd": "go install github.com/tomnomnom/waybackurls@latest && go install github.com/tomnomnom/gf@latest && sudo cp ~/go/bin/waybackurls /usr/bin&& sudo cp ~/go/bin/gf /usr/bin"
        },
        {
            "name": [
                "getallurls", "httpx-toolkit",
                "assetfinder", "findomain",
                "brutespray", "subfinder",
                "amass", "dnsx",
                "s3scanner", "ffuf", "ruby",
                "nmap", "nuclei",
            ],
            "command": "sudo apt install",
        },
        {
            "name": ["aquatone-discover","aquatone-scan"],
            "command":"multiple",
            "cmd": "sudo gem install aquatone",
        },
        {
            "name": ["urlhunter"],
            "command": "multiple",
            "cmd": "go install -v github.com/utkusen/urlhunter@latest &&  sudo cp ~/go/bin/urlhunter /usr/bin",
        },
        {
            "name":["snap"],
            "command":"multiple",
            "cmd": "sudo apt install snapd && sudo systemctl enable --now snapd.socket "
        },
        {
            "name": ["dalfox"],
            "command": "multiple",
            "cmd": "sudo snap install dalfox && sudo cp /snap/bin/dalfox /usr/bin"
        },
        {
            "name": ["Gxss"],
            "command": "multiple",
            "cmd": "go install github.com/KathanP19/Gxss@latest && sudo cp ~/go/bin/Gxss /usr/bin"
        },
        {
            "name": ["chad"],
            "command": "multiple",
            "cmd": "pipx install google-chad && pipx upgrade google-chad && playwright install chromium",
        },
        {
            "name": ["bbot", "uro"], 
            "command": "pipx install"
        },
        {
            "name": ["snallygaster"],
            "command": "pipx install ",
        },
        {"name": ["parsero"], "command": "sudo apt install "},
        {
            "name": ["subzy"],
            "command": "multiple",
            "cmd": "go install -v github.com/PentestPad/subzy@latest && sudo cp ~/go/bin/subzy /usr/bin",
        },
        {
            "name": ["subjack"],
            "command": "multiple",
            "cmd": "go install -v github.com/haccer/subjack@latest && sudo cp ~/go/bin/subjack /usr/bin",
        },
    ]

    HEADLINE = f"\n{color.HEADER}[*]INFO[*]{color.ENDC}\n"
    EXTERNAL_HELPER_STRING = f"""{HEADLINE}
Module performs an end-to-end external assessment of the supplied domain by
running a series of phases that are chained together. Each phase produces its
own artifact directory inside [output_directory/External/<domain>_<timestamp>/].

{color.OKCYAN}{color.UNDERLINE}Phases (run in order){color.ENDC}:
    {color.OKGREEN}1. recon       {color.ENDC} subdomain enumeration (subfinder, assetfinder, amass, findomain) + dnsx resolution
    {color.OKGREEN}2. probe       {color.ENDC} HTTP probing of resolved hosts via httpx-toolkit (status, title, tech)
    {color.OKGREEN}3. screenshots {color.ENDC} gowitness screenshots of every alive web service
    {color.OKGREEN}4. takeover    {color.ENDC} subdomain takeover detection (subzy / subjack)
    {color.OKGREEN}5. urls        {color.ENDC} historical URL collection (gauplus / waybackurls) + sensitive-file filter
    {color.OKGREEN}6. vulns       {color.ENDC} nuclei templated vulnerability scan against alive hosts
    {color.OKGREEN}7. ports       {color.ENDC} all-ports nmap scan with vuln scripts; open ports only, no ping discovery (final step)

{color.OKCYAN}{color.UNDERLINE}:params{color.ENDC} :
        {color.OKGREEN}domain {color.ENDC}      Target domain (e.g. example.com)
        {color.OKGREEN}phases {color.ENDC}      Optional comma-separated subset of phases to execute
        {color.OKGREEN}safe_mode {color.ENDC}   Lower-impact profile: in-scope filtering, capped targets, reduced concurrency
                                and high-noise phases disabled (recon, probe, urls only).
        {color.OKGREEN}operator_tag{color.ENDC} Optional identifier added to safe-mode HTTP headers and run metadata.

A consolidated [external_report.md] is written into the run directory at the
end of every assessment; it lists each phase's artifacts and counts.

{HEADLINE}"""
