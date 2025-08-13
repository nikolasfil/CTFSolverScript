Module ctfsolver.inline.parser
==============================
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

Classes
-------

`Parser(*args, **kwargs)`
:   

    ### Descendants

    * ctfsolver.inline.inline_tool.InlineTool

    ### Methods

    `add_arguments(self)`
    :   Add command line arguments to the parser.

    `automatic_functions_gathering(self, self_save=True)`
    :   Automatically gather all functions that start with "function_"
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

    `main(self)`
    :