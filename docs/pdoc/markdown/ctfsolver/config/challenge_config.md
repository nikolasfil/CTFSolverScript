Module ctfsolver.config.challenge_config
========================================

Classes
-------

`ChallengeConfig(*args, **kwargs)`
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

    ### Ancestors (in MRO)

    * ctfsolver.managers.manager_folder.ManagerFolder

    ### Methods

    `create_challenge_config(self)`
    :

    `get_template_data(self)`
    :

    `initialize_challenge(self)`
    :

    `update_challenge_info(self, data)`
    :