class MobileInterface:
    def __init__(self) -> None:

        pass

    def user_interaction():

        print("Running Mobile scripts")
        package_name = input(
            "Please provide the package name (com.example.packagename)\n"
        )
        # TODO: validate input is valid string

        return {"package_name": package_name}
