from _Utils.locate_dependencies import LocateDependencies
from _Utils.colors import bcolors
from _Handlers.install_dependencies import InstallDepencies
from pprint import pprint

dependecies = LocateDependencies()
install_package = InstallDepencies()

def main():
    if len(dependecies.to_install) == 0:
        print(f"{bcolors.FAIL}[!] No Packages To install..{bcolors.ENDC}")
        # Start Our test scripts
    else:
        install_package.install_packages(dependecies.to_install)
        #pprint(dependecies.to_install)

if __name__ == "__main__":
    main()