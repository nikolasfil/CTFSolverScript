Module ctfsolver.managers.manager_file
======================================
manager_file.py

This module defines the ManagerFile class, which serves as a unified interface for file and folder management operations within the CTF solver application. It inherits functionality from ManagerFilePcap, ManagerFileRegex, and ManagerFolder, enabling support for pcap file handling, regex-based file searches, and folder management.

Classes:
    ManagerFile: Combines methods from multiple manager classes to provide comprehensive file and folder operations, including searching for base64-encoded strings within files.

Usage:
    Instantiate ManagerFile to access file and folder management utilities, such as searching for patterns or handling specific file types.

Note:
    Some methods are deprecated and may be replaced by more specific implementations.

Classes
-------

`ManagerFile(*args, **kwargs)`
:   ManagerFile class for handling file operations in CTF solving context.
    This class inherits from ManagerFilePcap, ManagerFileRegex, and ManagerFolder,
    providing methods for initializing file-related ancestors and searching for base64
    strings within files.
    Attributes:
        None
    Methods:
        __init__(*args, **kwargs):
            Initializes the ManagerFile instance and its relevant ancestors.
        initializing_file_ancestors(*args, **kwargs):
            Initializes ManagerFolder and ManagerFilePcap ancestors.
        search_for_base64(file, *args, **kwargs):
            Deprecated. Use search_for_base64_file instead.
        search_for_base64_file(file, *args, **kwargs):
            Searches for base64 strings in the specified file.
                file (str): Path to the file to search.
                display (bool, optional): If True, prints the output. Defaults to False.
                save (bool, optional): If True, returns the output as a list. Defaults to False.
                strict (bool, optional): If True, applies strict matching. Defaults to False.
                list: List of matched base64 strings if save is True; otherwise, None.
    
    Initialize the class

    ### Ancestors (in MRO)

    * ctfsolver.managers.manager_files_pcap.ManagerFilePcap
    * ctfsolver.managers.manager_files_re.ManagerFileRegex
    * ctfsolver.managers.manager_folder.ManagerFolder

    ### Descendants

    * ctfsolver.src.ctfsolver.CTFSolver

    ### Methods

    `initializing_file_ancestors(self, *args, **kwargs)`
    :   Initializes the file ancestor managers for the current instance.
        This method explicitly calls the initializers of `ManagerFolder` and `ManagerFilePcap`
        with the provided arguments, ensuring that the current object is properly set up
        with folder and file pcap management capabilities.
        Args:
            *args: Variable length argument list passed to the ancestor initializers.
            **kwargs: Arbitrary keyword arguments passed to the ancestor initializers.
        Returns:
            None

    `search_for_base64(self, file, *args, **kwargs)`
    :   Deprecated: Use search_for_base64_file

    `search_for_base64_file(self, file, *args, **kwargs)`
    :   Description:
        Search for base64 string in the file
        
        Args:
            file (str): File to search for the base64 string
            display (bool, optional): Display the output. Defaults to False.
            save (bool, optional): Save the output. Defaults to False.
        
        Returns:
            list: List of output if save is True