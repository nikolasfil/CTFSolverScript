"""
inline_tool.py

This module provides the InlineTool class, which extends the Parser class to offer command-line functionality for managing Capture The Flag (CTF) challenges and related folder structures. The InlineTool class integrates configuration management, error handling, and folder linking operations, allowing users to initialize the tool, create and manage CTF challenges, and set up the required directory structure as specified in the global configuration.

Classes:
    InlineTool(Parser): Handles command-line operations for CTF management, including folder creation, initialization, challenge creation, and folder linking.

Usage:
    Run this module as a script to interact with the InlineTool via command-line arguments.

Attributes:
    CONFIG (Config): Global configuration object for managing tool settings.
    ManagerFile: Handles file and folder operations.
    ManagerError: Handles error management and reporting.

Example:
    python inline_tool.py --command init
"""

from ctfsolver.inline.parser import Parser
from pathlib import Path
from ctfsolver.config.global_config import CONFIG
from ctfsolver.managers.manager_file import ManagerFile
from ctfsolver.error.manager_error import ManagerError


class InlineTool(Parser):
    """
    InlineTool provides command-line management for CTF (Capture The Flag) challenges and related folder structures.

    This class extends the Parser base class to handle various commands for initializing configuration,
    creating and managing CTF challenges, and linking folders. It uses a ManagerFile for file operations
    and a ManagerError for error handling.

    Attributes:
        error_handler (ManagerError): Handles errors and exceptions.
        home_path (Path): The user's home directory path.
        manager (ManagerFile): Manages file and folder operations.
        functions (dict): Dictionary mapping command names to their corresponding handler methods.


    Methods:
        main():
            Entry point for command execution. Dispatches commands based on parsed arguments.

        print_help_message():
            Prints help information for the command-line interface.

        function_folders():
            Creates the folder structure as specified by the global configuration.

        function_init():
            Initializes the tool by setting up global configuration and necessary directories/files.

        function_create_ctf():
            Placeholder for creating a new CTF challenge.

        function_ctf():
            Manages CTF challenges, including category and site navigation.

        function_link():
            Links CTF folders using the Linking class.
    """

    def __init__(self, *args, **kwargs):
        """
        Initializes the class instance.
        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        Initializes the parent class and sets up the error handler using ManagerError.
        """

        super().__init__(*args, **kwargs)
        self.error_handler = ManagerError()

    def main(self):
        """
        Executes the main logic of the inline tool.
        This method sets up the home path and file manager, then processes the command-line arguments.
        If a command is provided, it attempts to execute the corresponding function using the error handler.
        If no command is specified, it prints the help message.
        Args:
            None
        Returns:
            None
        """

        self.home_path = Path.home()
        self.manager = ManagerFile()
        if self.args.command:
            self.error_handler.try_function(
                function=self.functions.get(self.args.command)
            )
        else:
            self.print_help_message()

    def print_help_message(self):
        """
        Prints the help message for the command-line parser.
        This method displays usage information and available options for the tool
        by invoking the parser's print_help() method. Intended to assist users in
        understanding how to use the command-line interface.
        Returns:
            None
        """
        # This should be enriched
        self.parser.print_help()

    def function_folders(self):
        """
        Ensures that the parent folder required for function organization is created.
        This method delegates the creation of the parent folder to the manager instance,
        which handles folder management operations.
        Returns:
            None

        Example:
            [data, docs, files, payloads]

        """
        self.manager.create_parent_folder()

    def function_init(self):
        """
        Initialize the inline tool by setting up the global configuration.
        This method is called when the inline tool is first run
        or when global configuration needs to be set up.
        It creates the necessary directories and files if they do not already exist.
        """

        CONFIG.initializing()

    def function_create_ctf(self):
        """
        Create a new CTF (Capture The Flag) challenge.
        This function is a placeholder for the actual implementation
        that would handle the creation of a CTF challenge.
        """
        print("Creating a new CTF challenge... (not implemented yet)")

    def function_ctf(self):
        """
        Manage CTF challenges.
        This function is a placeholder for the actual implementation
        that would handle the management of CTF challenges.
        """

        CONFIG.get_content()
        ctf_data_dir = CONFIG.content.get("directories").get("ctf_data")

        path_building = Path(self.home_path, ctf_data_dir)

        if self.args.category:
            path_building = Path(path_building, self.args.category)
            if not path_building.exists():
                raise FileNotFoundError(
                    f"Category '{self.args.category}' does not exist in {path_building}"
                )

            if self.args.site:
                path_building = Path(path_building, self.args.site)
                if not path_building.exists():
                    raise FileNotFoundError(
                        f"Site '{self.args.site}' does not exist in {path_building}"
                    )

        _, dirs, _ = self.manager.single_folder_search(path=path_building)
        print(dirs)

    def function_link(self):
        """
        Link CTF folders.
        This function initializes the Linking class to manage CTF folder links.
        """
        pass


if __name__ == "__main__":
    example = InlineTool()
    print(example.functions)
