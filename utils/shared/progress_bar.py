import curses
from .validators import Validator


class ProgressBar(Validator):
    """Display Scan Progress and saves the Live hosts to a file using the
    Filehandler Module
    """

    def __init__(self) -> None:
        super().__init__()
        self.total_scanned = 0
        self.total_hosts = 0  # total
        self.live_hosts = set()
        self.unresponsive_hosts = set()

    def set_total_hosts(self, total: int):
        self.total_hosts = total

    def set_live_ip(self, ip):
        self.live_hosts.add(ip)

    def set_unresponsive_ip(self, ip):
        self.unresponsive_hosts.add(ip)

    def update_ips(self,
                   filename: str,
                   mode: str,
                   ip: str,
                   is_alive: bool,
                   stdscr,
                   save_file: callable,
                   generate_filename: callable,
                   existing_unresponsive_ips: set):
        """Update the scan progress and save both live and unresponsive hosts

        :param save_file:                 Function to save csv file
        :param filename:                  Name of the file being saved
        :param mode:                      Scanning mode used [scan|resume]
        :param ip:                        IP address being saved to file
        :param is_alive:                  True or False 
        :param existing_unresponsive_ips: Set containing unresponsive IPs [avoid duplication]
        """
        filename_ = generate_filename(mode,is_alive,filename)
        if is_alive:
            self.live_hosts.add(ip)  
            save_file(filename_, ip)

        else:
            self.unresponsive_hosts.add(ip)
            condition = mode == "scan" or (mode == "resume" and ip not in existing_unresponsive_ips)
            if condition:
                save_file(filename_, ip)
                if mode == "resume":
                    existing_unresponsive_ips.add(ip)  
        
        self.total_scanned += 1
        if stdscr is not None:  # Only update UI if curses is active
            self.display(stdscr)

    def display(self, stdscr):
        if stdscr is None:
            return
        height, width = stdscr.getmaxyx()
        output_height = height - 3
        output_width = width * 3 // 4
        stdscr.clear()

        curses.curs_set(0)

        # Initialize color pairs
        curses.start_color()
        # Alive IPs - green text
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)

        live_list = list(self.live_hosts)[:output_height]
        dead_list = list(self.unresponsive_hosts)[:output_height]
        # Display Alive IPs
        for idx, host in enumerate(live_list):
            stdscr.addstr(idx, 0, f"[+] {host} ", curses.color_pair(1))

        # Display Dead IPs
        for idx, dead_ip in enumerate(dead_list):
            stdscr.addstr(
                idx, output_width // 2, f"[-] {dead_ip}", curses.color_pair(2)
            )

        # Display Progress Bar
        progress_message = f"Progress: {self.total_scanned}/{self.total_hosts}"
        stdscr.addstr(height - 2, 0, progress_message)

        stdscr.refresh()
