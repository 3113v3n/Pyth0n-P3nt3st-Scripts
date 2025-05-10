import os
import subprocess
from pathlib import Path
from pprint import pprint
import re
#from shared.validators import Validator

# TODO: get from validator class
def file_exists(filename) -> bool:
        exists = os.path.exists(filename)
        return exists

def is_valid_subdomain(subdomain, root_domain):
    pattern =rf"^(?:[\w-]+\.)+{re.escape(root_domain)}$"
    return re.match(pattern, subdomain.strip()) is not None

def filter_subdomain(subdomains,root_domain):
    return {sub.strip() for sub in subdomains if is_valid_subdomain(sub,root_domain)}

def shell_command(command, tool,debug):
    try:
        print(f"\nExecuting command: {' '.join(command)}")
        result = subprocess.run(command, check=True,capture_output=True,text=True)
        if debug:
            pprint(result.stdout.splitlines())
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"An error occured while running {tool.title()}: {e}")


class DomainRecon:
    def __init__(self):
        #self.validators = Validator()
        self.debug = True

    # Enumeration
    
    def enumerate_subdomain(self,domain: str, output_dir: Path):
        """Enumerate subdomains using the following tools: subfinder, assetfinder, amass, findomain, dnsx
        :param domain: Target domain
        :param output_dir: the output directory
        """
        def format_domain(domain_):
            # Remove http:// or https:// if present
            return domain_.replace("https://","").replace("http://","").strip("/")
        
        formatted_domain = format_domain(domain)
        subdomain_file=f"{output_dir}/{formatted_domain}_subdomains.txt"
        resolved_subdomains = f"{output_dir}/resolved_{formatted_domain}_subdomains.txt"

        if not file_exists(subdomain_file):
            print(f"Running recon on :{formatted_domain}")
            #subfinder
            sublister_result =self.run_sublister(formatted_domain, self.debug)
            #assetfinder
            assetfinder_result =self.run_assetfinder(formatted_domain,self.debug)
            #Findomain
            findomain_result =self.run_findomain(formatted_domain, self.debug)
            #Amass
            amass_result =self.run_amass(formatted_domain, self.debug)

            #filter subdomains
            all_subs = filter_subdomain(
                sublister_result + assetfinder_result  + findomain_result + amass_result, 
                formatted_domain)
            
            if self.debug:
                print(f"\nWritting {len(all_subs)} unique subdomains to {subdomain_file}")

            with open(subdomain_file, "w") as f:
                for subdomain in sorted(all_subs):
                    f.write(f"{subdomain}\n")

        if not file_exists(resolved_subdomains):
            #Dnsx
            print(f"\n[+] Resolving subdomains with dnsx and writing results to {resolved_subdomains}")
            self.run_dnsx(subdomain_file, resolved_subdomains)
        
    @staticmethod
    def run_sublister(target:str,debug_mode:bool):
        sub_command = [
            "subfinder",
            "-d",
            target,
            "-all",
            "-recursive"
            ]
        return shell_command(sub_command,"subfinder",debug_mode)

    @staticmethod
    def run_assetfinder(target:str, debug_mode:bool):
        command = [
            "assetfinder",
            "--subs-only",
            target
        ] 
        return shell_command(command, "assetfinder",debug_mode)

    @staticmethod
    def run_amass(target,debug_mode:bool):
        command=[
            "amass",
            "enum",
            "-passive",
            "-d",
            target          
        ]
        return shell_command(command, "amass",debug_mode)

    @staticmethod
    def run_findomain(target,debug_mode:bool):
        command=[
        "findomain",
        "-t",
        target
        ]
        return shell_command(command, "findomain",debug_mode)
    
    @staticmethod
    def run_dnsx(input_file, output_file):
        command = [
            "dnsx",
            "-a",
            "-resp",
            "-silent",
            "-l",
            input_file
        ]
        with open(output_file , "w") as file:
            subprocess.run(command, stdout=file,check=True)
            
        
        

if __name__ == "__main__":
    recon = DomainRecon()
    recon.enumerate_subdomain(
        "https://kcbgroup.com",
        "/home/vl4d1m1r/Pyth0n-P3nt3st-Scripts/output_directory/External")