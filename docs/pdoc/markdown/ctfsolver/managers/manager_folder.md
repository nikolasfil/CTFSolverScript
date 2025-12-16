Module ctfsolver.managers.manager_folder
========================================
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

    CONFIG (dict): Global configuration dictionary imported from ctfsolver.config.

Dependencies:
    pathlib, inspect, os, ast, collections.defaultdict

Classes
-------

`ManagerFolder(*args, **kwargs)`
:   ManagerFolder provides utilities for managing folder structures and files for CTF (Capture The Flag) challenges.
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
        find_function_from_file(file_path, function_name): Finds and returns the source code of a function from a file.
        folfil(folder, file): Returns the full path of a file within a folder.
        folders_file(*folders, file): Returns the full path of a file within nested folders.
        challenge_folder_structure(*args, **kwargs): Checks the structure of challenge folders.
        recursive_folder_search(function, *args, path=None, **kwargs): Recursively applies a function to folders and files.
        single_folder_search(*args, **kwargs): Applies a function to the contents of a single folder.
    Example:
        manager = ManagerFolder(file="challenge.txt", verbose=True)
        manager.prepare_space(files=["input.txt", "output.txt"])
    
    Initialize the class

    ### Descendants

    * ctfsolver.config.challenge_config.ChallengeConfig
    * ctfsolver.find_usage.manager_gathering.ManagerGathering
    * ctfsolver.managers.manager_file.ManagerFile
    * ctfsolver.venv.manager_venv.ManagerVenv

    ### Methods

    `challenge_folder_structure(self, *args, **kwargs)`
    :   Description:
            Recursively search

    `check_empty_folder(self, folder)`
    :   Description:
            Check if the folder is empty

    `check_folder_exists(self, folder: str) ‑> str | bool`
    :

    `clean_folders(self, folders: list = None)`
    :   Description:
            Clean the space by deleting the folders that remain empty

    `copy_folder(self, source, destination)`
    :   Description:
        Copies the folder and all its contents to the destination.
        
        Args:
            source (str): Source folder to copy
            destination (str): Destination folder to copy to
        
        Returns:
            None

    `create_ctf_structure(self, category, site, name, verbose=False, download=False, **kwargs)`
    :   Description:
            Create the CTF folder structure

    `create_parent_folder(self)`
    :   Description:
            Create the parent folder of the file that called the class if they don't exist

    `delete_folder(self, folder)`
    :   Description:
        Deletes the folder and all its contents.
        
        Args:
            folder (str): Folder to delete
        
        Returns:
            None

    `download_automove(self, category: str, challenge_name: str, challenge_path, checker: bool = False, verbose: bool = False)`
    :   Description:
        Moves the downloaded files to the challenge folder structure
        
        Args:
            category (str): Category of the challenge
            challenge_name (str): Name of the challenge to search in the downloads
            challenge_path (str): Path of the challenge to move

    `exec_on_files(self, files: list[str], func: <built-in function callable>, *args, **kwargs)`
    :   Description:
        Execute a function on all the file list with the arguments provided
        
        Args:
            files (list): List of files to execute the function
            func (function): Function to execute
        
        Returns:
            list: List of output of the function

    `exec_on_folder(self, folder: pathlib._local.Path, func: <built-in function callable>, *args, **kwargs)`
    :   Description:
        Execute a function on all the files in the folder with the arguments provided
        
        Args:
            folder (str): Folder to execute the function
            func (function): Function to execute
        
        Returns:
            list: List of output of the function

    `exec_on_folder_files(self, folder: pathlib._local.Path, func: <built-in function callable>, func_args=[], func_kwargs={}, *args, **kwargs)`
    :   Description:
        Execute a function on all the files in the folder with the arguments provided
        
        Args:
            folder (str): Folder to execute the function
            func (function): Function to execute
        
        Returns:
            list: List of output of the function

    `folders_file(self, *folders, file)`
    :   Description:
            Get the full path of the file in the folder
        
        Args:
            folders (list): List of folders to get the file
        
        Returns:
            str: Full path of the file

    `folfil(self, folder, file)`
    :   Description:
            Get the full path of the file in the folder
        
        Args:
            folder (str): Folder to get the file
            file (str): File to get the full path
        
        Returns:
            str: Full path of the file

    `get_challenge_file(self)`
    :   Description:
            Get the challenge file and assign it to the self.challenge_file for ease of access

    `get_current_dir(self)`
    :

    `get_parent(self)`
    :   Description:
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

    `get_solution_file(self, *args, solution_name='solution.py', save=False, display=False, **kwargs)`
    :   Description:
            Get the solution file and assign it to the self.solution_file for ease of access
        
        Args:
            solution_name (str, optional): Name of the solution file. Defaults to "solution.py".
            save (bool, optional): Save the solution file. Defaults to False.
        
        Returns:
            str: Path of the solution file if save is True

    `handling_global_config(self)`
    :

    `init_for_challenge(self, *args, **kwargs)`
    :   Initializes the class for the challenge.
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

    `initializing_all_ancestors(self, *args, **kwargs)`
    :   Description:
            Initializes all the ancestors of the class

    `prepare_space(self, files=None, folder=None, test_text='flag{test}')`
    :   Creates files with specified content in a given folder if they do not already exist.
        Args:
            files (list, optional): List of filenames to create. Defaults to an empty list.
            folder (str or Path, optional): Path to the folder where files will be created.
            Defaults to self.folder_files.
            test_text (str, optional): Content to write into each created file. Defaults to "flag{test}".
        Returns:
            None

    `recursive_folder_search(self, function, *args, path=None, **kwargs)`
    :   Description:
            Recursively search for the file in the folder

    `search_files(self, directory, exclude_dirs, search_string, save=False, display=False)`
    :   Description:
        Search for a string in the files in the directory
        
        Args:
            directory (str): Directory to search for the string
            exclude_dirs (list): List of directories to exclude
            search_string (str): String to search for
            save (bool, optional): Save the output. Defaults to False.
            display (bool, optional): Display the output. Defaults to False.
        
        Returns:
            list: List of output if save is True

    `search_for_pattern_in_file(self, file, func=None, display=False, save=False, *args, **kwargs)`
    :   Description:
        Search for a pattern in the file and return the output
        
        Args:
            file (str): File to search for the pattern
            func (function, optional): Function to search for the pattern. Defaults to None.
            display (bool, optional): Display the output. Defaults to False.
            save (bool, optional): Save the output. Defaults to False.
        
        Returns:
            list: List of output if save is True

    `setup_named_folders(self)`
    :   Initializes and sets up named folder paths as attributes and in a dictionary.
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

    `single_folder_search(self, *args, **kwargs)`
    :   Searches a single folder and applies a specified function to its contents.
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