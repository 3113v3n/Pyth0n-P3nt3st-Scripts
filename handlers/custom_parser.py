
import sys
from utils.shared import Bcolors,Config

from argparse import ArgumentParser, Action


class CustomArgumentParser(ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(
            f"\n{Bcolors.FAIL}[!]Error:{Bcolors.ENDC} {message}\n")
        sys.exit(2)


class CustomHelp(Action,Config):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)
        self.color = Bcolors
        self.config = Config()

    def __call__(self, parser, namespace, values, option_string=None):
       
        simple_help_text = self.config.SUMMARY_HELPER_TEXT 
        more_text = self.config.EXTRA_HELPER_TEXT
        
        # Check if a verbose flag is set in namespace
        # print(namespace)

        full_help_text = simple_help_text + more_text
        print(full_help_text)
        sys.exit(0)
