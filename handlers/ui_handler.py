import tkinter as tk

THEME_COLOR = "#375362"


class PentestUI:
    def __init__(self) -> None:
        self.window = tk.Tk()  # type: ignore
        self.window.title("Pentest Tool")
        self.window.config(padx=20, pady=20, bg=THEME_COLOR)
        self.scanned_ips = 0
        self.canvas = tk.Canvas(width=700, height=400, background="white")
        # Labels
        self.score_label = tk.Label(
            text=f"Scanned Ips: {self.scanned_ips}", fg="#FFFFFF", bg=THEME_COLOR
        )
        # Output
        self.output_text = tk.scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=60, height=20, state=tk.DISABLED
        )

        # Grid System
        self.score_label.grid(column=1, row=0)
        self.canvas.grid(row=1, column=0, columnspan=3, pady=30)
        self.output_text.grid(column=1, row=2, columnspan=2)
        self.window.mainloop()

