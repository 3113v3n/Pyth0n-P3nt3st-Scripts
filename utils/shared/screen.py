from utils.shared.colors import Bcolors
from utils.shared import Loader
from time import sleep
class ScreenHandler(Bcolors):
    def __init__(self):
       pass 
   
    @staticmethod
    def create_menu_selection(
                     menu_selection: str,
                     options: list | tuple,
                     check_range_string: str,
                     check_range_function: callable,
                     start_color: str,
                     end_color: str,
                     **kwargs):
        print(menu_selection)
        for option in options:
            # Ensure both scanner menu and file extension are sorted for
            display_option = option["name"] if "scanner" in kwargs else option.upper()
            print(f" {start_color}[{options.index(option) + 1}]{end_color}"
                  f" {display_option}"
                  )
        return check_range_function(f"\n {check_range_string}", options)
    
    @staticmethod
    def loader(message: str, end_message: str):
        with Loader(message, end_message):
            for _ in range(10):
                sleep(0.25) 
                
    def get_file_path(self, prompt: str):
        """Get and validate file path from user"""
        while True:
            file_path = input(prompt).strip()
            if not file_path:
                print(f"{self.WARNING}\n[!] Path cannot be empty{self.ENDC}")
                continue
            if not self.check_folder_exists(file_path):
                print(f"{self.FAIL}\n[!] No such folder exists{self.ENDC}")
                continue
            return file_path
        
    def get_output_filename(self, prompt: str = "[+] Please enter the output filename: "): 
        """Get output filename from user"""
        
        while True:
            filename = input(prompt).strip()
            if not filename:
                print(f"{self.WARNING}\n[!] Filename cannot be empty{self.ENDC}")
                continue
            return filename
        
    def display_files_onscreen(self,
                      directory:str,  
                      display_saved_files:callable,
                      **kwargs)->tuple:
        """Display files in directory with extension filter"""
        files = display_saved_files(
            directory,
            scan_extension=kwargs.get("scan_extension"),
            resume_scan=kwargs.get("resume_scan",False),
            display_applications=kwargs.get("display_applications",False)
                                    )
        if not files:
            raise FileNotFoundError(f"{self.WARNING}\n[!] No files found in {directory}{self.ENDC}")
        return files
    
    