import curses
from .validators import Validator


class ProgressBar(Validator):
    """Display Scan Progress and saves the Live hosts to a file using the
    Filehandler Module
    """

    def __init__(self) -> None:
        super().__init__()
        self.total_scanned = 0
        self.total_hosts = 0 #total
        self.live_hosts = []
        self.unresponsive_hosts = []

    def set_total_hosts(self,total:int):
        self.total_hosts = total

    def update_ips(self, save_file_to_csv, output_file, stdscr, ip, is_alive, mode):
        """Update the scan progress and save both live and unresponsive hosts"""
        basename = self.get_filename_without_extension(output_file)
        if is_alive:

            output_file = (
                output_file.replace("_unresponsive_hosts", "")
                if mode == "resume"
                else output_file
            )
            self.live_hosts.append(ip)
            save_file_to_csv(output_file, ip)

        else:
            self.unresponsive_hosts.append(ip)
            filename = (
                f"{basename}_unresponsive_hosts.csv"
                if "unresponsive_hosts" not in basename
                else f"{basename}.csv"
            )
            save_file_to_csv(filename, ip)

        self.total_scanned += 1
        self.display(stdscr)

    def display(self, stdscr):
        height, width = stdscr.getmaxyx()
        output_height = height - 3
        output_width = width * 3 // 4
        stdscr.clear()

        curses.curs_set(0)

        # Initialize color pairs
        curses.start_color()
        curses.init_pair(
            1, curses.COLOR_GREEN, curses.COLOR_BLACK
        )  # Alive IPs - green text
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        # Display Alive IPs
        for idx, host in enumerate(self.live_hosts[-output_height:]):
            stdscr.addstr(idx, 0, f"[+] {host} ", curses.color_pair(1))

        # Display Dead IPs
        for idx, dead_ip in enumerate(self.unresponsive_hosts[-output_height:]):
            stdscr.addstr(
                idx, output_width // 2, f"[-] {dead_ip}", curses.color_pair(2)
            )

        # Display Progress Bar
        progress_message = f"Progress: {self.total_scanned}/{self.total_hosts}"
        stdscr.addstr(height - 2, 0, progress_message)

        stdscr.refresh()
