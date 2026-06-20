from handlers.messages import DisplayHandler
from utils.shared import Commands


class NetExec(Commands):
    def __init__(self) -> None:
        super().__init__()

    def gen_relay_list(self, input_file, output_file) -> list:
        DisplayHandler._emit_message(f"\n{input_file}\n{output_file}")
        return self.run_os_commands(
            ["netexec", "smb", str(input_file), "--gen-relay-list", str(output_file)]
        )
