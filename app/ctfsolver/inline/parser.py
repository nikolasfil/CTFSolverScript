"""
parser.py

This module provides the Parser class for handling command-line arguments and dynamic command discovery
for the Inline tool. It leverages argparse and argcomplete to support flexible command-line interfaces,
automatically gathering available command methods and exposing them as selectable commands.

Classes:
    Parser: Handles argument parsing, dynamic command discovery, and provides an interface for
        extending command functionality.

Usage:
    Instantiate the Parser class to parse command-line arguments and access dynamically discovered
    commands. Extend the class with methods prefixed by 'function_' to add new commands.

Example:
    parser = Parser()
    args = parser.args
    # Access parsed arguments and available commands via parser.command_list

"""

import argparse
import argcomplete


class Parser:
    def __init__(self, *args, **kwargs):
        self.parser = argparse.ArgumentParser(
            description="Inline tool for various operations"
        )
        self.automatic_functions_gathering()
        self.add_arguments()

    def automatic_functions_gathering(self, self_save=True):
        """
        Automatically gather all functions that start with "function_"
        and store them in the command_list attribute.
        This allows for dynamic command handling based on the available functions.
        The functions are expected to be methods of the InlineTool class.
        The gathered functions can be used as commands for the tool.
        The self_save parameter determines whether to save the gathered functions
        in the instance's command_list attribute.
        This is useful for dynamically updating the available commands without hardcoding them.

        Args:
            self_save (bool, optional):  Defaults to True.

        Returns:
            list: A list of function names that start with "function_".
        """
        self.functions = {
            func[9:]: getattr(self, func)
            for func in dir(self)
            if callable(getattr(self, func))
            and not func.startswith("__")
            and func.startswith("function_")
        }

        if self_save:
            self.command_list = list(sorted(self.functions.keys()))
        return self.functions

    def main(self):
        # This is an abstract method
        pass

    def add_arguments(self):
        """
        Add command line arguments to the parser.

        """

        # The initial command
        self.parser.add_argument(
            "command",
            choices=self.command_list,
            help="Specify the operation to perform",
            nargs="?",
            default=None,
            # type=str,
            # metavar="COMMAND",
        )

        self.parser.add_argument(
            "--dry-run",
            "-d",
            action="store_true",
            help="Run the command without making any changes",
            required=False,
        )

        self.parser.add_argument(
            "--category",
            "-c",
            # choices=self.categories,
            type=str,
            help="Specify the category for the operation",
            required=False,
        )

        self.parser.add_argument(
            "--site",
            "-s",
            # choices=self.all_sites,
            type=str,
            help="Specify the site for the operation",
            required=False,
        )

        # Gather all the arguments parsed
        self.args = self.parser.parse_args()
