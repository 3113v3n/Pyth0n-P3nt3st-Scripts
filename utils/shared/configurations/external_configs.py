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
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf "
                   "go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
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
                "s3scanner", "ffuf", "ruby"
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
Module scans the targets domain [domain.xy.z] and uses different techniques
    to try and enumerate information on the target.

{color.OKCYAN}{color.UNDERLINE}:params{color.ENDC} :
        {color.OKGREEN}domain {color.ENDC}  Target domain to scan

{HEADLINE}"""
