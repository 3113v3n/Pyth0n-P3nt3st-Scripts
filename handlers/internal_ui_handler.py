class InternalInterface:
    def __init__(self) -> None:

        pass

    def user_interaction(get_subnet, config, color, filemanager):
        print(" Running Internal PT modules ")
        subnet = get_subnet
        mode = input(config.internal_mode_choice).lower()

        # Ensure correct mode is selected by user
        while mode not in ["scan", "resume"]:
            mode = input(config.internal_choice_error)

        if mode == "resume":
            try:
                # returns an ip address if a file exists
                # returns None if no file exists

                resume_ip = filemanager.display_saved_files(filemanager.output_directory)

                if resume_ip is None:
                    raise ValueError("No Previously saved file present")

                # output file
                output_file = filemanager.filepath
                subnet = f"{resume_ip}/{subnet.split('/')[1]}"

            except ValueError as error:
                print(f"{color.FAIL}[!] Cant use this module, {error}{color.ENDC}")
                print(f"\nDefaulting to {color.OKCYAN}SCAN{color.ENDC} mode")
                mode = "scan"
                subnet = get_subnet()
                output_file = input("[+] Provide a name for your output file: ")

        elif mode == "scan":
            # TODO: file validations
            output_file = input("[+] Provide a name for your output file: ")

        return {
            "subnet": subnet,
            "mode": mode,
            "output": output_file,
        }
