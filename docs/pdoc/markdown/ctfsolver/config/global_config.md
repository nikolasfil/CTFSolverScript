Module ctfsolver.config.global_config
=====================================
Global configuration management for the CTFSolverScript package.

This module provides the `GlobalConfig` class, which handles the creation, initialization,
and access of a global configuration file stored in the user's home directory. The configuration
file is used to store persistent settings required by the CTFSolverScript inline tool.

Classes:
    GlobalConfig: Manages the global configuration file, including creation, initialization,
                  reading, and attribute/dictionary-style access to configuration values.

Attributes:
    CONFIG (GlobalConfig): Singleton instance of the GlobalConfig class for global access.

Example:
    >>> from ctfsolver.config.global_config import CONFIG
    >>> from ctfsolver.config import CONFIG
    >>> CONFIG.initializing()  # Initializes the global configuration

Typical usage involves initializing the configuration (creating the file and writing initial
content if necessary) and accessing configuration values via attribute or dictionary-style access.

Raises:
    AttributeError: If an attribute is accessed that does not exist in the configuration.
    KeyError: If a key is accessed that does not exist in the configuration.

Classes
-------

`GlobalConfig(*args, **kwargs)`
:   Initializes the global configuration for the CTF solver application.
    This constructor sets the path to the global configuration file and loads its content.
    
    Attributes:
        global_config_file_path (Path): Path to the global configuration JSON file.
    
    Raises:
        Any exceptions raised by `get_content()` will propagate.

    ### Methods

    `check_config_content(self)`
    :

    `creating(self)`
    :   Creates a global configuration file in the user's home directory.
        
        This method ensures that the required directories and configuration file exist,
        creating them if necessary. It is typically called during the initial run of the
        inline tool or when global configuration setup is required.
        
        Args:
            None
        
        Returns:
            None
        
        Raises:
            OSError: If the directory or file cannot be created due to permission issues.

    `get_content(self)`
    :   Get the content of the global configuration file.
        This method reads the global configuration file and returns its content
        as a dictionary.
        If the file does not exist or is empty, it returns an empty dictionary.
        It is intended to be used to retrieve the current global configuration
        settings for use in the inline tool or other parts of the application.
        
        
        Returns:
            dict: The content of the global configuration file as a dictionary.

    `initial_content(self)`
    :   Sets the initial content of the global configuration file.
        
        This method loads a configuration template from 'config_template.json' and writes it to the global
        configuration file if the file is empty or does not exist. If the template file is missing, a default
        initial content is used instead.
        
        Args:
            None
        
        Returns:
            None
        
        Raises:
            FileNotFoundError: If the template file or global configuration file path does not exist.
            json.JSONDecodeError: If the template file contains invalid JSON.
        
        Side Effects:
            Writes initial configuration content to the global configuration file if it is empty.
            Prints status messages to the console.

    `initializing(self)`
    :   Initialize global configuration settings.
        This method can be used to set up any necessary global configurations
        required by the inline tool.