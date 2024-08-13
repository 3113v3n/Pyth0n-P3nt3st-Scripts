from utils import Commands


class NetExec(Commands):
    def __init__(self) -> None:
        pass

    def gen_relay_list(self, input_file, output_file) -> list:
        print(f"\n{input_file}\n{output_file}")
        return self.run_os_commands(f"netexec smb {input_file} --gen-relay-list {output_file}")
