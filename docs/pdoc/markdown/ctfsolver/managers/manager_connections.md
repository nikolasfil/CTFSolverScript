Module ctfsolver.managers.manager_connections
=============================================
manager_connections.py

This module provides the ManagerConnections class for managing connections to CTF challenges,
supporting both local and remote connection types using the pwntools library.

Classes:
    ManagerConnections: Handles connection setup, interaction, and communication with CTF challenges.

Typical usage example:
    manager = ManagerConnections(url="example.com", port=1337, conn="remote")
    manager.initiate_connection()
    output = manager.recv_lines(number=3, display=True, save=True)
    manager.send_menu(choice=1, menu_num=3, menu_text="Your choice:")

Attributes:
    pwn (module): Reference to the pwntools library.
    url (str): Remote URL for connection.
    port (int): Remote port for connection.
    conn_type (str): Type of connection ("local" or "remote").
    conn: Active connection object.
    menu_num (int): Number of menu options.
    menu_text (str): Text prompt for menu selection.
    debug (bool): Debug mode flag.

    ValueError: If required menu parameters are not provided.
    DeprecationWarning: If deprecated methods are used.
    EOFError: If the connection closes unexpectedly during data reception.

Classes
-------

`ManagerConnections(*args, **kwargs)`
:   Manages connections to CTF challenges, supporting both local and remote modes.
    This class provides methods to initiate and manage connections to CTF challenges,
    either by spawning a local process or connecting to a remote host. It also offers
    utilities for interacting with typical menu-driven CTF binaries, including sending
    choices, receiving lines, and handling menu prompts.
    Attributes:
        pwn: The pwntools module or object used for process and remote connections.
        url (str): The remote host URL or IP address.
        port (int): The remote host port.
        conn_type (str): Type of connection, either 'local' or 'remote'.
        conn: The active connection object (process or remote).
        menu_num (int): Number of menu options expected.
        menu_text (str): Text prompt expected before sending a menu choice.
        debug (bool): Flag to enable debug mode.
    Methods:
        __init__(*args, **kwargs):
            Initializes the ManagerConnections instance with connection parameters.
        initiate_connection(*args, **kwargs):
            Initiates the connection based on the specified connection type.
        connect(*args, **kwargs):
            Connects to the challenge locally or remotely, depending on conn_type.
        recv_menu(number=1, display=False, save=False):
            Deprecated. Use recv_lines instead.
        recv_lines(number=1, display=False, save=False):
            Receives a specified number of lines from the connection.
        send_menu(choice, menu_num=None, menu_text=None, display=False, save=False):
            Sends a choice to a menu-driven binary, handling menu prompts and output.
        recv_send(text, lines=None, text_until=None, display=False, save=False):
            Receives lines and/or text until a prompt, then sends a response.
        send(text, encode=True):
            Sends text to the connection, optionally encoding it.
        recv_until(text, **kwargs):
            Receives data until a specified delimiter is encountered.
    
    Initializes the connection manager with the provided arguments.
    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.
            url (str, optional): The URL for the connection.
            port (int, optional): The port number for the connection.
            conn (str, optional): The type of connection.
            debug (bool, optional): Enables debug mode. Defaults to False.
    Attributes:
        pwn: Placeholder for future use.
        url (str): The URL for the connection.
        port (int): The port number for the connection.
        conn_type (str): The type of connection.
        conn: The connection object (initialized as None).
        menu_num: The menu number (initialized as None).
        menu_text: The menu text (initialized as None).
        debug (bool): Debug mode status.

    ### Descendants

    * ctfsolver.src.ctfsolver.CTFSolver

    ### Methods

    `connect(self, *args, **kwargs) ‑> None`
    :   Description:
            Connects to the challenge based on the connection type.
            If the connection type is remote, it connects to the url and port provided.
            If the connection type is local, it starts a process with the file provided.
        
        
            local:
                kwargs :
                    argv: Any | None = None,
                    shell: bool = False,
                    executable: Any | None = None,
                    cwd: Any | None = None,
                    env: Any | None = None,
                    ignore_environ: Any | None = None,
                    stdin: int = PIPE,
                    stdout: PTY | int = PTY if not IS_WINDOWS else PIPE,
                    stderr: int = STDOUT,
                    close_fds: bool = True,
                    preexec_fn: Any = lambda : None,
                    raw: bool = True,
                    aslr: Any | None = None,
                    setuid: Any | None = None,
                    where: str = 'local',
                    display: Any | None = None,
                    alarm: Any | None = None,
                    creationflags: int = 0

    `initiate_connection(self, *args, **kwargs) ‑> None`
    :   Initiates a connection using the specified connection type and parameters.
        Args:
            *args: Variable length argument list to be passed to the connection method.
            **kwargs: Arbitrary keyword arguments to be passed to the connection method.
        Returns:
            None

    `recv_lines(self, number=1, display=False, save=False, *args, **kwargs)`
    :   Description:
            Receives the output of the menu based on the number of lines provided.
            If display is True, it prints the output of everything received.
            If save is True, it saves the output in a list and returns it.
        
        Args:
            number (int, optional): Number of lines to receive . Defaults to 1.
            display (bool, optional): Displayes the lines received. Defaults to False.
            save (bool, optional): Saves the lines received to a list. Defaults to False.
        
        Returns:
            list: list of the lines received if save is True

    `recv_menu(self, number=1, display=False, save=False)`
    :

    `recv_send(self, text, lines=None, text_until=None, display=False, save=False)`
    :   Description:
            Receives lines and sends a response.
            It can receive a number or lines, and/or specific text.
            If save is True, it saves the output of the menu in a list and returns it.
            If display is True, it prints the output of everything received.
        
        Args:
            choice (int or str): Choice to send to the menu
            menu_num (int, optional): Number of options printed in the menu. Defaults to None.
            menu_text (str, optional): Text that the menu asks before sending your choice. Defaults to None.
            display (bool, optional): Variable to print every received line. Defaults to False.
            save (bool, optional): . Defaults to False.
        Returns:
            list: List of output of the menu if save is True

    `recv_until(self, text, **kwargs) ‑> bytes`
    :   Description:
            Receive data until one of `delims`(text) provided is encountered. It encodes the text before sending it.
            Wrapper for self.conn.recvuntil(text.encode())
            Can also drop the ending if drop is True. If the request is not satisfied before ``timeout`` seconds pass, all data is buffered and an empty string (``''``) is returned.
        Args:
            text (str): Text to receive until
            **kwargs: Additional keyword arguments to pass to the recv
                - drop (bool, optional): Drop the ending.  If :const:`True` it is removed from the end of the return value. Defaults to False.
                - timeout (int, optional): Timeout in seconds. Defaults to default.
        
        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied
        
        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

    `send(self, text, encode=True) ‑> None`
    :   Description:
            Sends the text to the connection after it encodes it.
            Wrapper for self.conn.sendline(str(text).encode())
        
        Args:
            text (str): Text to send

    `send_menu(self, choice, menu_num=None, menu_text=None, display=False, save=False)`
    :   Description:
            Gets the menu num either from the class or from the function call and saves it to the class.
            Gets the menu text that the menu is providing, receives until the menu asks for choice and then send out the choice.
            If save is True, it saves the output of the menu in a list and returns it.
            If display is True, it prints the output of everything received.
        
        Args:
            choice (int or str): Choice to send to the menu
            menu_num (int, optional): Number of options printed in the menu. Defaults to None.
            menu_text (str, optional): Text that the menu asks before sending your choice. Defaults to None.
            display (bool, optional): Variable to print every received line. Defaults to False.
            save (bool, optional): . Defaults to False.
        Returns:
            list: List of output of the menu if save is True