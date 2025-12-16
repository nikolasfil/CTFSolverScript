Module ctfsolver.folders.link_ctf_folders
=========================================

Classes
-------

`Linking(*args, **kwargs)`
:   ManagerFile class for handling file operations in CTF solving context.
    This class inherits from ManagerFilePcap, ManagerFileRegex, ManagerFolder, and ManagerFunction,
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

    * ctfsolver.managers.manager_file.ManagerFile
    * ctfsolver.managers.manager_files_pcap.ManagerFilePcap
    * ctfsolver.managers.manager_files_re.ManagerFileRegex
    * ctfsolver.managers.manager_folder.ManagerFolder
    * ctfsolver.managers.manager_functions.ManagerFunction

    ### Methods

    `get_all_sites(self)`
    :

    `get_categories(self)`
    :

    `get_challenges(self, category=None, site=None, folder=True)`
    :

    `handling_global_config(self)`
    :

    `main(self)`
    :

    `temp(self)`
    :