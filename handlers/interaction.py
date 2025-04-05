
class InteractionHandler:
    """Class responsible for handling interactions with the user.
    Switches between different modes [interactive and arguments]

    Usage: script_name.py [ --(interactive | arguments | help) ] 

    Args:
        --interactive: Run the script in interactive mode.
        --arguments: Run the script with arguments.
        --help: Show this help message and exit.

    [arguments]:
        Run script with arguments.(one liner)
        Usage: script_name.py --arguments  [OPTIONS] [Flags] 

        [OPTIONS]: Options for the script. (mobile|internal|password|va|external)
                mobile :    Handle mobile assessment
                internal:   Handle internal PT
                password:   Perform password related operation
                va:         Handle vulnerability assessment
                external    Handle External PT

        [Flags]: Flags for the script .
                --help: Show help message for individual module and exit.
                

    """