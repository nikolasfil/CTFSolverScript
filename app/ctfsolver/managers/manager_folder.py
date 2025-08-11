"""
manager_folder.py

This module provides the `ManagerFolder` class for managing folder structures and file operations
in the context of CTF (Capture The Flag) challenges. It offers utilities for initializing challenge
folders, preparing and cleaning up files, searching for patterns, and introspecting Python files
for function definitions.

Classes:
    ManagerFolder: Handles creation, management, and introspection of challenge-related folders and files.

Typical usage example:
    manager = ManagerFolder(file="challenge.py", verbose=True)
    manager.create_parent_folder()
    manager.prepare_space(files=["input.txt", "output.txt"])
    functions = manager.get_functions_from_file("challenge.py")

    CONFIG (dict): Global configuration dictionary imported from ctfsolver.config.

Dependencies:
    pathlib, inspect, os, ast, collections.defaultdict

"""

from pathlib import Path
import inspect
import os
import ast
from collections import defaultdict
from ctfsolver.config import CONFIG


class ManagerFolder:
    """

    ManagerFolder provides utilities for managing folder structures and files for CTF (Capture The Flag) challenges.
    This class handles the creation, organization, and manipulation of challenge-related directories and files,
    including payloads, data, and solution scripts. It offers methods for searching files, executing functions
    on files, cleaning up empty directories, and extracting function definitions from Python files.
        verbose (bool): Enables verbose output for debugging and logging.
        Path (type): Reference to the pathlib.Path class for file system operations.
        parent (Path): The resolved parent directory of the calling file.
        file (str): The filename associated with the challenge.
        folders_name_list (list): List of folder names to be managed.
        folders (defaultdict): Mapping of folder names to their Path objects.
        folder_payloads (Path): Path to the payloads folder.
        folder_data (Path): Path to the data folder.
        folder_files (Path): Path to the files folder.
        challenge_file (Path): Path to the challenge file.
        solution_file (Path): Path to the solution file.
    Methods:
        __init__(*args, **kwargs): Initializes the ManagerFolder instance.
        init_for_challenge(*args, **kwargs): Sets up attributes and folders for a challenge.
        handling_global_config(): Loads global configuration for folder names.
        initializing_all_ancestors(*args, **kwargs): Initializes ancestor classes (placeholder).
        get_parent(): Determines and sets the parent directory of the calling file.
        setup_named_folders(): Creates and assigns paths for named folders.
        create_parent_folder(): Creates parent folders if they do not exist.
        prepare_space(files=None, folder=None, test_text="flag{test}"): Prepares challenge space by creating files and folders.
        clean_folders(folders: list = None): Removes empty folders.
        check_empty_folder(folder): Checks if a folder is empty.
        get_challenge_file(): Assigns the challenge file path.
        get_solution_file(*args, solution_name="solution.py", save=False, display=False, **kwargs): Retrieves the solution file path.
        search_for_pattern_in_file(file, func=None, display=False, save=False, *args, **kwargs): Searches for a pattern in a file.
        exec_on_files(folder, func, *args, **kwargs): Executes a function on all files in a folder.
        search_files(directory, exclude_dirs, search_string, save=False, display=False): Searches for a string in files within a directory.
        get_self_functions(): Returns a list of callable methods of the class.
        get_function_reference(function, file): Finds references to a function in a file.
        get_functions_from_file(file_path): Extracts function names from a Python file.
        find_function_from_file(file_path, function_name): Finds and returns the source code of a function from a file.
        folfil(folder, file): Returns the full path of a file within a folder.
        folders_file(*folders, file): Returns the full path of a file within nested folders.
        challenge_folder_structure(*args, **kwargs): Checks the structure of challenge folders.
        recursive_folder_search(function, *args, path=None, **kwargs): Recursively applies a function to folders and files.
        single_folder_search(*args, **kwargs): Applies a function to the contents of a single folder.
    Example:
        manager = ManagerFolder(file="challenge.txt", verbose=True)
        manager.prepare_space(files=["input.txt", "output.txt"])
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the class
        """
        self.verbose = kwargs.get("verbose", False)
        self.Path = Path
        self.handling_global_config()
        self.get_parent()
        init_challenge = kwargs.get("init_for_challenge", True)
        if init_challenge:
            self.init_for_challenge(*args, **kwargs)

    def init_for_challenge(self, *args, **kwargs):
        """
        Initializes the class for the challenge.
        This method sets up the necessary attributes and folders required for the challenge.
        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
                - file (str): The file associated with the challenge.
                - debug (bool, optional): Flag to enable or disable debug mode. Defaults to False.
                - folders_name_list (list, optional): A custom list of folder names. Defaults to None.
        Attributes:
            file (str): The file associated with the challenge.
            debug (bool): Indicates whether debug mode is enabled.
            folders_name_list (list or None): A custom list of folder names, if provided.
            folders_names_must (list): The default list of required folder names.
        """

        self.file = kwargs.get("file")
        self.debug = kwargs.get("debug", False)

        # """
        # Folder names list
        # """

        self.setup_named_folders()
        self.get_challenge_file()

    def handling_global_config(self):
        self.folders_name_list = CONFIG["structures"]["ctf_folder"]

    def initializing_all_ancestors(self, *args, **kwargs):
        """
        Description:
            Initializes all the ancestors of the class
        """
        pass

    def get_parent(self):
        """
        Description:
                Retrieves the parent directory of the file that invoked the current class.

            This method determines the file path of the script that instantiated the class,
            resolves its parent directory, and adjusts the result based on a predefined list
            of folder names.

        Attributes:
            self.parent (Path or None): The resolved parent directory of the calling file.
            self.file_called_frame (list): The stack frame of the calling file.
            self.file_called_path (Path): The file path of the calling file.

        Behavior:
            - If the parent directory's name is in `self.folders_name_list`, the method
              sets `self.parent` to the grandparent directory instead.

        Note:
            Ensure that `self.folders_name_list` is defined and contains the folder names
            to be checked before calling this method.
        """
        self.parent = None

        self.file_called_frame = inspect.stack()
        self.file_called_path = Path(self.file_called_frame[-1].filename)
        self.parent = Path(self.file_called_path).parent.resolve()

        if self.parent.name in self.folders_name_list:
            self.parent = self.parent.parent

    def setup_named_folders(self):
        """

        Initializes and sets up named folder paths as attributes and in a dictionary.
        This method creates Path objects for the 'data', 'files', and 'payloads' folders
        relative to the parent directory, and assigns them to corresponding attributes.
        It also initializes a defaultdict to store folder paths for each name in
        `self.folders_name_list`, mapping each folder name to its Path object.

        Attributes set:
            folder_payloads (Path): Path to the 'payloads' folder.
            folder_data (Path): Path to the 'data' folder.
            folder_files (Path): Path to the 'files' folder.
            folders (defaultdict): Dictionary mapping folder names to their Path objects.


        Raises:
            AttributeError: If `self.parent` or `self.folders_name_list` is not defined.

        """

        self.folder_payloads = None
        self.folder_data = None
        self.folder_files = None

        self.folder_data = Path(self.parent, "data")
        self.folder_files = Path(self.parent, "files")
        self.folder_payloads = Path(self.parent, "payloads")

        # Perhaps a new way of calling the folders

        self.folders = defaultdict(None)

        for folder in self.folders_name_list:
            self.folders[folder] = Path(self.parent, folder)

    def create_parent_folder(self):
        """
        Description:
            Create the parent folder of the file that called the class if they don't exist
        """

        # In next versions this function's name should change

        for folder in self.folders.values():
            if not folder.exists():
                folder.mkdir()

    def prepare_space(self, files=None, folder=None, test_text="flag{test}"):
        """
        Creates files with specified content in a given folder if they do not already exist.
        Args:
            files (list, optional): List of filenames to create. Defaults to an empty list.
            folder (str or Path, optional): Path to the folder where files will be created.
            Defaults to self.folder_files.
            test_text (str, optional): Content to write into each created file. Defaults to "flag{test}".
        Returns:
            None
        """

        files = files if files else []
        folder = folder if folder else self.folder_files

        for file in files:
            if not Path(folder, file).exists():
                with open(Path(folder, file), "w") as f:
                    f.write(test_text)

    def clean_folders(self, folders: list = None):
        """
        Description:
            Clean the space by deleting the folders that remain empty
        """
        folders = folders if folders is not None else self.folders.values()

        for folder in folders:
            if self.verbose:
                print(folder)
            if self.check_empty_folder(folder):
                folder.rmdir()
                # Check if the folder has

    def check_empty_folder(self, folder):
        """
        Description:
            Check if the folder is empty
        """
        if folder.exists():
            if self.verbose:
                print(folder.iterdir())
            return not any(folder.iterdir())
        return False

    def get_challenge_file(self):
        """
        Description:
            Get the challenge file and assign it to the self.challenge_file for ease of access
        """
        if self.file and self.folder_files:
            self.challenge_file = Path(self.folder_files, self.file)
        elif not self.folder_files:
            if self.debug:
                print("Data folder not found")

    def get_solution_file(
        self, *args, solution_name="solution.py", save=False, display=False, **kwargs
    ):
        """
        Description:
            Get the solution file and assign it to the self.solution_file for ease of access

        Args:
            solution_name (str, optional): Name of the solution file. Defaults to "solution.py".
            save (bool, optional): Save the solution file. Defaults to False.

        Returns:
            str: Path of the solution file if save is True
        """

        self.solution_file = None
        if self.folders["payloads"]:
            self.solution_file = Path(self.folders["payloads"], solution_name)
            if not self.solution_file.exists():
                self.solution_file = None
                if display:
                    print(f"Solution file {solution_name} not found")

        if save:
            return self.solution_file

    def search_for_pattern_in_file(
        self, file, func=None, display=False, save=False, *args, **kwargs
    ):
        """
        Description:
        Search for a pattern in the file and return the output

        Args:
            file (str): File to search for the pattern
            func (function, optional): Function to search for the pattern. Defaults to None.
            display (bool, optional): Display the output. Defaults to False.
            save (bool, optional): Save the output. Defaults to False.

        Returns:
            list: List of output if save is True

        """
        if save:
            output = []
        if func is None:
            return None

        with open(file, "r") as f:
            for line in f:
                result = func(line, *args, **kwargs)
                if result is not None:
                    if display:
                        print(result)
                    if save:
                        output.extend(result)
        if save:
            return output

    def exec_on_files(self, folder, func, *args, **kwargs):
        """
        Description:
        Execute a function on all the files in the folder with the arguments provided

        Args:
            folder (str): Folder to execute the function
            func (function): Function to execute

        Returns:
            list: List of output of the function
        """

        save = kwargs.get("save", False)
        display = kwargs.get("display", False)
        if save:
            output = []
        for file in folder.iterdir():
            out = func(file, *args, **kwargs)
            if save and out is not None:
                output.extend(out)
            if display and out is not None:
                print(out)
        if save:
            return output

    def search_files(
        self, directory, exclude_dirs, search_string, save=False, display=False
    ):
        """
        Description:
        Search for a string in the files in the directory

        Args:
            directory (str): Directory to search for the string
            exclude_dirs (list): List of directories to exclude
            search_string (str): String to search for
            save (bool, optional): Save the output. Defaults to False.
            display (bool, optional): Display the output. Defaults to False.

        Returns:
            list: List of output if save is True
        """
        if save:
            output = []

        for root, dirs, files in os.walk(directory):
            # Exclude specified directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r") as f:
                        # Check if the search string is in the file
                        if search_string in f.read():
                            if display:
                                print(file_path)
                            if save:
                                output.append(file_path)
                except (IOError, UnicodeDecodeError):
                    # Handle files that cannot be opened or read
                    continue

        if save:
            return output

    def get_self_functions(self):
        """
        Description:
        Get the functions of the class
        """

        return [
            func
            for func in dir(self)
            if callable(getattr(self, func)) and not func.startswith("__")
        ]

    def get_function_reference(self, function, file):
        """
        Description:
        Get the reference of the function in the file
        """

        if function not in self.get_self_functions():
            raise ValueError(f"Function {function} not found in the class")

        output = []

        with open(file, "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if function in line:
                    output.append(line)
        return output

    def get_functions_from_file(self, file_path):
        """
        Description:
        Get the functions from the file
        """

        output = []
        with open(file_path, "r") as file_path:
            file_content = file_path.read()

        # Parse the file content into an AST
        tree = ast.parse(file_content)

        # Define a visitor class to find the function definition
        class FunctionDefFinder(ast.NodeVisitor):
            def __init__(self):
                self.function_def = None

            def visit_FunctionDef(self, node):
                output.append(node.name)
                # Continue visiting other nodes
                self.generic_visit(node)

        # Create an instance of the visitor and visit the AST
        finder = FunctionDefFinder()
        finder.visit(tree)

        # If the function was found, return its definition
        return output

    def find_function_from_file(self, file_path, function_name):
        """
        Description:
        Get the functions from the file
        """

        with open(file_path, "r") as file_path:
            file_content = file_path.read()

        # Parse the file content into an AST
        tree = ast.parse(file_content)

        # Define a visitor class to find the function definition
        class FunctionDefFinder(ast.NodeVisitor):
            def __init__(self):
                self.function_def = None

            def visit_FunctionDef(self, node):
                if node.name == function_name:
                    self.function_def = node
                # Continue visiting other nodes
                self.generic_visit(node)

        # Create an instance of the visitor and visit the AST
        finder = FunctionDefFinder()
        finder.visit(tree)

        # If the function was found, return its definition
        if finder.function_def:
            return ast.unparse(finder.function_def)
        else:
            return None

    def folfil(self, folder, file):
        """
        Description:
            Get the full path of the file in the folder

        Args:
            folder (str): Folder to get the file
            file (str): File to get the full path

        Returns:
            str: Full path of the file

        """

        folder = self.folders[folder]

        if folder is None:
            raise ValueError("Folder not found")

        full_path = self.Path(folder, file)

        return full_path

    def folders_file(self, *folders, file):
        """
        Description:
            Get the full path of the file in the folder

        Args:
            folders (list): List of folders to get the file

        Returns:
            str: Full path of the file

        """

        # folder = self.folders[folder]

        full_path = self.Path(*folders, file)

        if full_path is None:
            raise ValueError("Folder not found")
        if not full_path.exists():
            raise ValueError("File not found")

        return full_path

    def challenge_folder_structure(self, *args, **kwargs):
        """
        Description:
            Recursively search
        """
        root = kwargs.get("root", None)
        dirs = kwargs.get("dirs", [])
        files = kwargs.get("files", [])

        # print(f"Root: {root}\nDirs: {dirs}\nFiles: {files}")

        # Checks with self.folder_names_must
        # Checks if there are laying files
        # If there are only folders from the must file it's correct . Else it needs change

        if len(files) > 0 or not all([dir in self.folders_names_must for dir in dirs]):
            print(f"Root: {root}")

        print(f"Root: {root}\nDirs: {dirs}\nFiles: {files}")
        return root, dirs, files

    def recursive_folder_search(self, function, *args, path=None, **kwargs):
        """
        Description:
            Recursively search for the file in the folder
        """

        exclude_list = kwargs.get("exclude", [])

        if path is None:
            path = self.parent

        for root, dirs, files in os.walk(path):
            if any([exclude in root for exclude in exclude_list]):
                continue

            print(f"Root: {root}\nDirs: {dirs}\nFiles: {files}")
            function(root, dirs, files, *args, **kwargs)

    def single_folder_search(self, *args, **kwargs):
        """
        Searches a single folder and applies a specified function to its contents.
        Args:
            *args: Additional positional arguments to pass to the specified function.
            **kwargs: Additional keyword arguments, including:
                - exclude (list, optional): A list of directory names to exclude from the search.
                - function (callable, optional): A function to apply to the folder's contents.
                  The function should accept the following arguments: root (str), dirs (list),
                  files (list), *args, and **kwargs.
                - path (str, optional): The path of the folder to search.
        Returns:
            tuple: A tuple containing:
                - root (str): The root directory of the search.
                - dirs (list): A list of subdirectories in the root directory, excluding those in the exclude list.
                - files (list): A list of files in the root directory.
        """

        exclude_list = kwargs.get("exclude", [])
        function = kwargs.get("function", None)
        path = kwargs.get("path", None)

        root, dirs, files = next(os.walk(path))
        # print(f"Root: {root}\nDirs: {dirs}\nFiles: {files}")

        # Exclude files
        dirs = [dir for dir in dirs if dir not in exclude_list]

        if function is not None:
            function(root, dirs, files, *args, **kwargs)

        return root, dirs, files
