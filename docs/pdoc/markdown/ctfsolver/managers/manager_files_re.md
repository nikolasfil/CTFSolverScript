Module ctfsolver.managers.manager_files_re
==========================================
manager_files_re.py

This module provides the ManagerFileRegex class for extracting printable strings from files using regular expressions.

Classes:
    ManagerFileRegex:
        A manager class for file operations involving regular expressions,
        including extracting printable ASCII strings from binary files.

Usage:
    Instantiate ManagerFileRegex and use its methods to process files for printable string extraction.

Example:
    manager = ManagerFileRegex()
    strings = manager.extract_strings("/path/to/file", min_length=4)

Attributes:
    None

Classes
-------

`ManagerFileRegex(*args, **kwargs)`
:   

    ### Descendants

    * ctfsolver.managers.manager_file.ManagerFile

    ### Methods

    `extract_strings(self, file_path, min_length=4)`
    :   Description:
            Extracts printable strings from a file
        
        Args:
            file_path (str): The path to the file
            min_length (int): The minimum length of the string to extract
        
        Returns:
            list: The list of strings

    `initializing_all_ancestors(self, *args, **kwargs)`
    :   Description:
            Initializes all the ancestors of the class