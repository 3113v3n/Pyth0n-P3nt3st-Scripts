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
            "name": ["gowitness"],
            "command": "multiple",
            "cmd": "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin",
        },
        {
            "name": [
                "getallurls",
                "httpx-toolkit",
                "assetfinder",
                "brutespray",
                "subfinder",
            ],
            "command": "sudo apt install",
        },
        {
            "name": ["urlhunter"],
            "command": "multiple",
            "cmd": "go install -v github.com/utkusen/urlhunter@latest &&  sudo cp ~/go/bin/urlhunter /usr/bin",
        },
        {
            "name": ["chad"],
            "command": "multiple",
            "cmd": "pipx install google-chad && pipx install --upgrade google-chad && playwright install chromium",
        },
        {"name": ["bbot"], "command": "pipx install"},
        {
            "name": ["python3-dnspython", "python3-urllib3", "python3-bs4"],
            "command": "sudo apt install",
        },
        {
            "name": ["snallygaster"],
            "command": "pipx install snallygaster ",
        },
        {"name": ["parsero"], "command": "sudo apt install "},
        {
            "name": ["subzy"],
            "command": "multiple",
            "cmd": "go install -v github.com/luKaSikic/subzy@latest && sudo cp ~/go/bin/subzy /usr/bin",
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
