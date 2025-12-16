Module ctfsolver.src.ctfsolver
==============================
ctfsolver.py

This module defines the CTFSolver class, which serves as the main entry point for managing
CTF (Capture The Flag) solving operations. The CTFSolver class inherits from several manager
classes to provide functionalities for file handling, cryptographic operations, network
connections, and error management. It includes methods for initializing all ancestor classes,
executing the main logic with exception handling, and representing the solver as a string.

Classes:
    CTFSolver: Main class that aggregates file, crypto, connection, and error management
               functionalities for CTF solving workflows.

Usage:
    Instantiate the CTFSolver class and invoke its methods to perform CTF-related tasks.
    The module can be run directly to initialize manager components.

Example:
    solver = CTFSolver(debug=True)
    solver.try_main()

Raises:
    Exception: Handles general exceptions during main execution.
    KeyboardInterrupt: Handles user interruptions gracefully.

Classes
-------

`CTFSolver(*args, **kwargs)`
:   CTFSolver is a composite manager class designed to facilitate solving Capture The Flag (CTF) challenges.
    It inherits functionality from ManagerFile, ManagerConnections, ManagerCrypto, and ManagerError, providing
    a unified interface for file management, network connections, cryptographic operations, and error handling.
    Attributes:
        debug (bool): Enables or disables debug mode for verbose output.
        parent (str): The name of the parent folder (inherited from ManagerFile).
    Methods:
        __init__(*args, **kwargs):
            Initializes all ancestor classes and sets up the CTFSolver instance.
        initializing_all_ancestors(*args, **kwargs):
            Initializes all ancestor classes (ManagerFile, ManagerCrypto, ManagerConnections, ManagerError).
        main():
            Placeholder for the main logic of the solver. Should be implemented with challenge-specific logic.
        try_main():
            Executes the main function, handling exceptions and user interruptions gracefully.
        __str__():
            Returns a string representation of the CTFSolver instance, including the parent folder name.
    
    Initialize the class

    ### Ancestors (in MRO)

    * ctfsolver.managers.manager_file.ManagerFile
    * ctfsolver.managers.manager_files_pcap.ManagerFilePcap
    * ctfsolver.managers.manager_files_re.ManagerFileRegex
    * ctfsolver.managers.manager_folder.ManagerFolder
    * ctfsolver.managers.manager_functions.ManagerFunction
    * ctfsolver.managers.manager_connections.ManagerConnections
    * ctfsolver.managers.manager_crypto.ManagerCrypto
    * ctfsolver.error.manager_error.ManagerError

    ### Descendants

    * ctfsolver.find_usage.gathering.Gathering
    * ctfsolver.folders.finding_writeups.Folder_Structure
    * ctfsolver.template.gathering_template.Gathering
    * ctfsolver.template.solution_template.Solution

    ### Methods

    `initializing_all_ancestors(self, *args, **kwargs)`
    :   Description:
            Initializes all the ancestors of the class

    `main(self)`
    :   Description:
            Placeholder for the main function

    `try_main(self)`
    :   Attempts to execute the main function of the class, handling exceptions gracefully.
        This method wraps the execution of the `main` method in a try-except block to handle
        any unexpected errors or user interruptions. If an exception occurs, it prints an
        error message with the exception details. If the process is interrupted by the user
        (e.g., via a keyboard interrupt), it prints a corresponding message.
        Exceptions:
            Exception: Catches and prints any general exceptions that occur during the
                       execution of the `main` method.
            KeyboardInterrupt: Handles user-initiated interruptions and prints a message.