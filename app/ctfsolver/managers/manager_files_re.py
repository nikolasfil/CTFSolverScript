"""
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

"""

import re


class ManagerFileRegex:
    def __init__(self, *args, **kwargs):
        # self.re = re
        pass

    def initializing_all_ancestors(self, *args, **kwargs):
        """
        Description:
            Initializes all the ancestors of the class
        """
        pass

    def extract_strings(self, file_path, min_length=4):
        """
        Description:
            Extracts printable strings from a file

        Args:
            file_path (str): The path to the file
            min_length (int): The minimum length of the string to extract

        Returns:
            list: The list of strings

        """
        with open(file_path, "rb") as f:
            # Read the entire file as binary
            data = f.read()

            # Use a regular expression to find sequences of printable characters
            # The regex matches sequences of characters that are printable (ASCII 32-126)
            # and have a minimum length defined by min_length
            strings = re.findall(rb"[ -~]{%d,}" % min_length, data)

            # Decode the byte strings to regular strings
            return [s.decode("utf-8", errors="ignore") for s in strings]
