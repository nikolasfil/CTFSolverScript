Module ctfsolver.folders.finding_writeups
=========================================

Classes
-------

`Folder_Structure(*args, **kwargs)`
:   Handles operations related to organizing, comparing, and displaying CTF challenge folders and writeups.
    
    This class provides methods to:
    - Retrieve and structure challenge and writeup directories.
    - Clean up writeup data by filtering out unwanted files and folders.
    - Normalize challenge and writeup names for comparison.
    - Find differences between available challenges and writeups.
    - Print formatted tables summarizing challenges, writeups, and their differences.
    
    Attributes:
        Inherits from CTFSolver, which should provide methods like single_folder_search and Path.
    
    Methods:
        printing_table(challenges):
            Prints a formatted table of challenges grouped by category and site.
    
        printing_table_diff(challenges):
            Prints a formatted table showing differences between challenges and writeups, including their source.
    
        getting_challenges(path=None, folder=True):
            Retrieves a nested dictionary of challenges or writeups from the specified directory path.
    
        writeup_cleanup(writeups, exclude=None):
            Cleans up the writeups dictionary by removing excluded categories and filtering out non-writeup files.
    
        lowering(challenges):
            Normalizes challenge names by removing punctuation, spaces, and converting to lowercase.
    
        differ(challenges, writeups):
            Compares challenges and writeups, returning a dictionary of differences by category and site.
    
        main():
            Main workflow to retrieve challenges and writeups, clean and compare them, and print the results.
    
    Initialize the class

    ### Ancestors (in MRO)

    * ctfsolver.src.ctfsolver.CTFSolver
    * ctfsolver.managers.manager_file.ManagerFile
    * ctfsolver.managers.manager_files_pcap.ManagerFilePcap
    * ctfsolver.managers.manager_files_re.ManagerFileRegex
    * ctfsolver.managers.manager_folder.ManagerFolder
    * ctfsolver.managers.manager_functions.ManagerFunction
    * ctfsolver.managers.manager_connections.ManagerConnections
    * ctfsolver.managers.manager_crypto.ManagerCrypto
    * ctfsolver.error.manager_error.ManagerError

    ### Methods

    `differ(self, challenges, writeups)`
    :

    `getting_challenges(self, path=None, folder=True)`
    :

    `lowering(self, challenges)`
    :

    `printing_table(self, challenges)`
    :   Prints a formatted table displaying CTF challenges grouped by category and site.
        Args:
            challenges (dict): A nested dictionary where the first-level keys are category names (str),
            the second-level keys are site names (str), and the innermost values are lists of challenge names (str).
        Example:
            challenges = {
            "Crypto": {
                "CTFsite1": ["ChallengeA", "ChallengeB"],
                "CTFsite2": ["ChallengeC"]
            },
            "Web": {
                "CTFsite3": ["ChallengeD"]
            }
            }
            printing_table(challenges)
        Output:
            Prints a table to the console with columns: index, category, site, and challenge name.

    `printing_table_diff(self, challenges)`
    :

    `writeup_cleanup(self, writeups, exclude=None)`
    :