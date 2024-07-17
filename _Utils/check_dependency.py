import subprocess
import os

"""
Sample script to help automate external recon phase
"""


def os_command(command):
    """Executes shell commands"""
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        text=True,
    )
    if result.returncode == 0:
        print(result.stdout.strip())
    return result


def check_requirements():
    """Checks if required tools exists within thw system"""
    tools = [
        "bbot",
        "gowitness",
        "brutespray",
        "assetfinder",
        "amass",
        "httpx-toolkit",
        "getallurls",
        "urlhunter",
        "exiftool",
        "chad",
        "snallygaster",
        "parsero",
        "subzy",
        "subjack",
    ]
    command = ""
    missing_tools = []
    for i in tools:
        command = f"which {i}"
        result = os_command(command=command)
        code = result.returncode
        if code != 0:
            missing_tools.append(i)  # update the missing tools

    return missing_tools


def folder_exists(folder_name, search_path="/"):
    folder_exists = False
    for folder, subfolder, file in os.walk(search_path):
        if folder_name in subfolder:
            print(f"the folder exists at path {os.path.join(folder,folder_name)}")
            folder_exists = True
            break
    return folder_exists


def install_missing_tools(tools_array):
    """Takes an array of tools and installs the missing tools"""
    for tool in tools_array:
        match tool:
            case "bbot":
                print(f"[+] Installing {tool} ...")
                os_command("pipx install bbot")
            case "gowitness":
                print(f"[+] Installing {tool} ...")
                os_command(
                    "go install github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/bin"
                )
            case "brutespray":
                print(f"[+] Installing {tool} ...")
                os_command("sudo apt-get install brutespray")
            case "assetfinder":
                print(f"[+] Installing {tool} ...")
                os_command("sudo apt install assetfinder")
            case "amass":
                print(f"[+] Installing {tool} ...")
                os_command("sudo apt install amass")
            case "httpx-toolkit":
                print(f"[+] Installing {tool} ....")
                os_command("sudo apt install httpx-toolkit")
            case "getallurls":
                print(f"[+] Installing {tool} ....")
                os_command("sudo apt install getallurls")
            case "urlhunter":
                print(f"[+] Installing {tool} ....")
                os_command(
                    "go install -v github.com/utkusen/urlhunter@latest && sudo cp ~/go/bin/urlhunter /usr/bin"
                )
            case "exiftool":
                print(f"[+] Installing {tool} ....")
                os_command("sudo apt-get -y install libimage-exiftool-perl")
            case "chad":
                print(f"[+] Installing {tool} ....")
                os_command("pip3 install google-chad")
                os_command("pip3 install --upgrade google-chad")
                os_command("playwright install chromium")
            case "snallygaster":
                print(f"[+] Installing {tool} ....")
                os_command("pip3 install snallygaster")
                os_command(
                    "sudo apt install python3-dnspython python3-urllib3 python3-bs4"
                )
            case "parsero":
                print(f"[+] Installing {tool} ...")
                os_command("sudo apt install parsero")
            case "subzy":
                print(f"[+] Installing {tool} ...")
                os_command(
                    "go install -v github.com/luKaSikic/subzy@latest && sudo cp ~/go/bin/subzy /usr/bin"
                )

            case "subjack":
                print(f"[+] Installing {tool} ...")
                os_command(
                    "go install -v github.com/haccer/subjack@latest && sudo cp ~/go/bin/subjack /usr/bin"
                )
            case _:
                print(f"[+] All tools are up to date")


def create_folder(folder_name):
    if not folder_exists(folder_name):
        #os.getcwd()
        folder_path = os.path.join(os.getcwd(), folder_name)
        os.makedirs(folder_path)
        print(f"Folder '{folder_name}' not found. Created at: {folder_path}")


def enumerate_subdomains(domain, output_directory):
    # OUTPUT_DIR = "/home/deloitte/Client-Audits/Zimbabwe/FBC/External"
    bbot_scan = f"bbot -t {domain} -f subdomain-enum -m naabu gowitness -n my_scan -o {output_directory}"
    amass_scan = f"amass enum -d {domain} | grep {domain}"
    dimitry = f"dmitry -wines -o dmitry_results.txt {domain}"
    harvester = f"theHarvester -f theharvester_results.xml -b baidu,bevigil,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,threatminer,urlscan,yahoo -l 500 -d {domain}"
    get_hostname = f"grep -Po '(?<=\<host\>)(?!\<(?:ip|hostname)\>)[^\s]+?(?=\<\/host\>)|(?<=\<hostname\>)[^\s]+?(?=\<\/hostname\>)' theharvester_results.xml | sort -uf | tee -a harvester-subdomains.txt"
    # urlhunter -o urlhunter_results.txt -date latest -keywords keywords.txt
    #
    # chad -sos no -d chad_results -tr 100 -q "ext:txt OR ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx" -s *.somedomain.com -o chad_results.json
    # exiftool -S chad_results | grep -Po '(?<=Author\:\ ).+' | sort -uf | tee -a people.txt
    # snallygaster --nowww somesite.com | tee snallygaster_results.txt
    # for subdomain in $(cat subdomains_live_long_http.txt); do snallygaster --nohttps --nowww "${subdomain}"; done | tee snallygaster_http_results.txt
    # subzy -concurrency 100 -timeout 3 -targets subdomains.txt | tee subzy_results.txt
    os_command(bbot_scan)
    os_command(amass_scan)
    os_command(dimitry)
    harvester_result = os_command(harvester)
    if harvester_result.returncode == 0:
        os_command(get_hostname)

    create_folder("nuclei-templates")


def main():
    install_missing_tools(check_requirements())
    create_folder("nuclei-templat3s")
    os_command("nuclei -ut nuclei-templat3s")


if __name__ == "__main__":
    main()
