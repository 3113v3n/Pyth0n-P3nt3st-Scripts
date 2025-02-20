from itertools import cycle
from shutil import get_terminal_size
from threading import Thread, Event
from time import sleep
from typing import Optional


class Loader:
    """
        A loader-like context manager

        Args:
            desc (str, optional): The loader's description. Default to "Loading...".
            end (str, optional): Final print. Default to "Done!"
            timeout (float, optional): Sleep time between prints. Default to 0.1.
    """
        
    DEFAULT_SPINNER ={
        "dots": ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"],
        "line": ["⣷", "⣯", "⣟", "⡿"],
        "pipe": ["┤", "┘", "┴", "└", "├", "┌", "┬", "┐"],
        "simple": ["-", "\\", "|", "/"],
        "arc": ["◐", "◓", "◑", "◒"],
        "circle": ["◡", "⊙", "◠", "⊕"],  
        'bounce': ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈'],   
        
        }
    def __init__(self, 
                 desc: str="Loading...", 
                 end: str="Done!", 
                 timeout: float=0.1,
                 spinner_type: str="dots",
                 loading_state: bool=False
                 ):     
        
        self.desc = desc
        self.end = end
        self.timeout = max(0.1, timeout)
        self.spinner = self.DEFAULT_SPINNER.get(spinner_type, self.DEFAULT_SPINNER["dots"])
        self.loading_state = loading_state
        
        self._done = Event()
        self._thread: Optional[Thread] = None
        self._cols = get_terminal_size((80, 20)).columns

    def start(self):
        """Start Animation"""
        if self._thread is None or not self._thread.is_alive():
            self._done.clear()
            self._thread = Thread(target=self._animate, daemon=True)
            self._thread.start()
       

    def _animate(self)->None:
        try:
            for frame in cycle(self.spinner):
                if self._done.is_set() or not self.loading_state:
                    break
                    
                output = f"\r{self.desc} {frame}"
                if len(output) > self._cols:
                    output = output[:self._cols]
                
                print(output, flush=True, end="")
                sleep(self.timeout)
                
        finally:
            # Clear the line and print end message
            print("\r" + " " * self._cols, end="", flush=True)
            if self.end:
                print(f"\r{self.end}", flush=True)

    

    def stop(self):
        """Stop Animation"""
        self.loading_state = False
        self._done.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.timeout * 2)

   

