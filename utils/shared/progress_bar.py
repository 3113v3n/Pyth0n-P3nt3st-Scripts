import curses
from .validators import get_filename_without_extension


class ProgressBar:
    """Display Scan Progress and saves the Live hosts to a file using the
    Filehandler Module
    """

    def __init__(self, total) -> None:
        self.total_scanned = 0
        self.total_hosts = total
        self.live_hosts = []
        self.unresponsive_hosts = []

    def update_ips(
            self, filemanager, output_file, stdscr, ip, is_alive, mode
    ):
        """Update the scan progress and save both live and unresponsive hosts"""
        basename = get_filename_without_extension(output_file)
        if is_alive:
            self.live_hosts.append(ip)
            filemanager.save_to_csv(output_file, ip, mode)

        else:
            self.unresponsive_hosts.append(ip)
            filename = f"{basename}_unresponsive_hosts.csv"
            filemanager.save_to_csv(filename, ip, mode)

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
