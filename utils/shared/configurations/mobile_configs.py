from ..colors import Bcolors


class MobileConfigs:
    color = Bcolors

    def __init__(self):
        pass
    mobile_packages = [
        # Mobile
        # Install on Device
        # 1. WiFi ADB
        # 2. Magisk Frida / SQlite
        # 3. Drozer
        {
            "name": ["apktool"],
            "command": "multiple",
            "cmd": "sudo apt -y install aapt \
                wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool \
                chmod +x apktool && cp apktool /usr/local/bin/apktool \
                wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar \
                chmod +x apktool.jar && cp apktool.jar /usr/local/bin/apktool.jar",
        },
        {
            "name": ["go"],
            "command": "multiple",
            "cmd": "wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf "
            "go1.22.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin",
        },
        {
            "name": [
                "adb",
                "d2j-dex2jar",
                "nuclei",
                "radare2",
                # "libusbmuxd-tools",
                "sqlite3",
                "sqlitebrowser",
                "xmlstarlet",
                "apksigner",
                "zipalign",
                "pkg-config",
                "checkinstall",
                "git",
                "autoconf",
                "automake",
                "usbmuxd",
            ],
            "command": "sudo apt-get -y install ",
        },
        {
            "name": ["objection", "file-scraper"],  # "frida-tools",
            "command": "pipx install",
        },
        {"name": ["java"], "command": "sudo apt install default-jdk -y"},
        {
            "name": ["property-lister"],
            "command": "pipx install --upgrade ",
        },
        {"name": ["plistutil"], "command": "apt-get -y install "},
    ]

    # MOBILE ANALYSIS CONSTANTS
    # Define regex patterns as raw strings for better readability and handling
    IOS_FILE_SEARCH = r"hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView"
    BEARER_REGEX = r"[^\w\d]+(basic|bearer)\s.+"
    HARDCODED_REGEX = (
        r"(\?access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key"
        r"|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer"
        r'|user)\w*(?:"\s*:\s*|\s*=).+'
    )
    HARDCODED_REGEX_2 = r"([^\w\d]+(to(_|\s)do|todo|note)\s|//|/\*|\*/).+"
    BASE64_REGEX = r"(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}=|[a-zA-Z0-9\+\/]{2}==)"
    IP_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    URL_REGEX = r"\w+://[\w\-\.\@\:\/\?\=\%\&\#]+"
    DEEPLINKS_IGNORE_REGEX = r"\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)"
    HEADLINE = f"\n{color.HEADER}[*]INFO[*]{color.ENDC}\n"
    MOBILE_HELPER_STRING = f"""{HEADLINE}
This module helps do static analysis on a mobile application using
various techniques.
The script decompiles the provided application and scans individual
files for potential valuable information

    {color.OKCYAN}{color.UNDERLINE}:params{color.ENDC} :

        {color.OKGREEN}filepath{color.ENDC}  The path to the folder containing your ({color.WARNING}iOS | Android{color.ENDC}) applications  :

    {color.OKCYAN}{color.UNDERLINE}:returns{color.ENDC}: 

        {color.OKGREEN}files{color.ENDC}     Files containing: [{color.WARNING} IP_address|URLs|Hardcoded_Strings|
                                        Base64_decoded_strings|nuclei results{color.ENDC} ]
            
{HEADLINE}"""
