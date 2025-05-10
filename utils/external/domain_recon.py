import subprocess
import Path


class DomainRecon:
    def __init__(self):
        pass

    # Enumeration
    def enumerate_subdomain(domain: str, output_dir: Path):
        """Enumerate subdomains using the following tools: subfinder, assetfinder, amass, findomain, dnsx
        :param domain: Target domain
        :param output_dir: the output directory
        """
        def format_domain(domain_):
            # Remove http:// or https:// if present
            return domain_.replace("https://","").replace("http://","").strip("/")
        
        formatted_domain = format_domain(domain)
        output=f"{output_dir}/subdomains.txt"
        #subfinder
        sub_command = [
            "subfinder",
            "-d",
            formatted_domain,
            "-all",
            "-recursive",
            "-o",
            output
            ]
        try:
            print(f"Running command: {''.join(sub_command)}")
            subprocess.run(sub_command, checks=True)
            print(f"Subfinder scan complete. Output saved to {output}")
        except subprocess.CalledProcessError as e:
            print(f"An error occured while running subfinder: {e}")


if __name__ == "__main__":
    recon = DomainRecon()
    recon.enumerate_subdomain("https://kcbgroup.com",".")