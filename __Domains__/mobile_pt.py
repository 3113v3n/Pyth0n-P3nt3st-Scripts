from __Handlers__.install_dependencies import run_os_commands


class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(self, apkname) -> None:
        self.package_name = apkname

    def find_package_in_device(self):
        run_os_commands(
            f"adb shell cmd package list packages | grep ${self.package_name}"
        )
