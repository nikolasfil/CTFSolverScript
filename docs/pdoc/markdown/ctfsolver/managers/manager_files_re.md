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

    `check_name_similarity_in_files(self, files: list, information: list, threshold: float = 70.0) ‑> list`
    :   Check for similar names in a list of files based on provided information.
        
        Args:
            information (list): List of strings to compare against file names.
            files (list): List of file names to check.
            threshold (float): Similarity threshold (0-100) to consider a match.
        
        Returns:
            list: List of files that have similar names above the threshold.

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

    `normalize_name(self, name: str) ‑> str`
    :   Normalize a file or folder name so different naming styles correlate.

    `string_similarity(self, str1: str, str2: str) ‑> float`
    :   Calculate the similarity ratio between two strings using rapidfuzz.
        
        Args:
            str1 (str): The first string.
            str2 (str): The second string.
        
        Returns:
            float: Similarity ratio between 0 and 100.