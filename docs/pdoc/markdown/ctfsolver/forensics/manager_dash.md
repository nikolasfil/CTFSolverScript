Module ctfsolver.forensics.manager_dash
=======================================
manager_dash.py

Dash-based visualization manager for network packet flows.

This module provides the ManagerDash class, which facilitates the conversion of network packet data (such as from pcap files using scapy)
into a format suitable for interactive graph visualization using Dash and Cytoscape. It includes utilities for converting packets to graph elements,
validating element structure, generating example graphs, and running a Dash web application for visual exploration of network flows.

Classes:
    ManagerDash: Manages the conversion of packet data to Cytoscape elements and sets up the Dash visualization interface.

Typical Usage Example:
    manager.elements = manager.example_element_creator()

Dependencies:
    - dash
    - dash_cytoscape
    - scapy

Classes
-------

`ManagerDash(*args, **kwargs)`
:   ManagerDash provides functionality for converting network packet data into elements suitable for graph visualization,
    validating element structure, and displaying interactive network graphs using Dash and Cytoscape.
    
    Attributes:
        elements (list[dict]): List of elements representing nodes and edges for visualization.
        title (str): Title of the Dash application.
        app: dash.Dash | None  # Dash application instance
    
    
    Methods:
        pcap_to_element_converter(packets, save=False):
            Converts a list of scapy Packet objects into visualization elements (nodes and edges) based on IP layer data.
    
        pcap_to_element_converter_timestamp(packets, save=False):
            Converts packets into elements including timestamp nodes, representing temporal flow in the network graph.
    
        elements_checker(elements):
            Validates the structure and content of a list of element dictionaries for compatibility with Cytoscape.
    
        example_element_creator():
            Generates a sample list of elements representing a simple network graph for demonstration purposes.
    
        setup_dash():
            Initializes and configures the Dash application layout and callbacks.
    
        setup_dash_layout():
            Defines the layout of the Dash application, including the Cytoscape graph and output display.
    
        setup_dash_functions():
            Sets up Dash callback functions for interactive node information display.
    
        run_dash():
            Validates elements and runs the Dash application for interactive network graph visualization.
    
    Initializes the manager_dash instance.
    
    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.
            title (str, optional): The title for the network graph. Defaults to "Interactive Network Graph".
    
    Attributes:
        elements (list): Stores elements related to the manager dashboard.
        title (str): Title of the interactive network graph.

    ### Methods

    `elements_checker(self, elements: list[dict]) ‑> bool`
    :   Description:
            Validates a list of dictionaries to ensure they meet specific structural and content requirements.
            Each dictionary in the list must contain a "data" key with a dictionary value, and the keys within
            the "data" dictionary must adhere to a predefined set of allowed keys. Additionally, certain key
            combinations are required to be present together.
        Args:
            elements (list[dict]): A list of dictionaries to validate. Each dictionary is expected to have
                                   a "data" key containing another dictionary.
        Returns:
            bool: Returns True if all dictionaries in the list meet the validation criteria, otherwise False.

    `example_element_creator(self)`
    :   Generates a list of elements representing a network graph in a format compatible with Cytoscape.
        Description:
            This method creates a representation of a network graph based on predefined data.
            Each node (IP address) and edge (connection between IPs) is converted into a dictionary
            format suitable for use with Cytoscape visualizations.
        Args:
            None
        Returns:
            list: A list of dictionaries where each dictionary represents a node or an edge in the graph.
        Example output:
            [
                {"data": {"id": "192.168.0.2", "label": "192.168.0.2"}},
                {"data": {"id": "8.8.8.8", "label": "8.8.8.8"}},
                {"data": {"source": "192.168.0.2", "target": "8.8.8.8"}},
                {"data": {"id": "192.168.0.3", "label": "192.168.0.3"}},
                {"data": {"source": "192.168.0.2", "target": "192.168.0.3"}},
                {"data": {"id": "10.0.0.1", "label": "10.0.0.1"}},
                {"data": {"source": "192.168.0.3", "target": "10.0.0.1"}}
            ]

    `pcap_to_element_converter(self, packets: list[scapy.packet.Packet], save: bool = False) ‑> list[dict]`
    :   Converts a list of scapy Packet objects into a list of elements suitable for visualization,
        extracting source and destination IPs and protocol information.
        
        Each packet with an IP layer contributes:
            - Two node elements (for source and destination IPs)
            - One edge element (representing the connection and protocol between source and destination)
        
        Args:
            packets (list[scapy.packet.Packet]): List of scapy Packet objects to process.
            save (bool, optional): If True, returns the generated elements list. If False, assigns it to self.elements.
        
        Returns:
            list[dict]: List of elements representing nodes and edges if save is True; otherwise, None.

    `pcap_to_element_converter_timestamp(self, packets: list[scapy.packet.Packet], save: bool = False) ‑> list[dict]`
    :   Description:
            Converts a list of scapy Packet objects from a pcap file into a list of elements suitable for graph visualization.
            Each packet's timestamp, source IP, destination IP, and protocol are extracted and represented as nodes and edges.
            Optionally saves the generated elements to the instance.
        
        Args:
            packets (list[scapy.packet.Packet]): List of scapy Packet objects to convert.
            save (bool, optional): If True, returns the elements list; otherwise, assigns it to self.elements. Defaults to False.
        
        Raises:
            AttributeError: If a packet does not have the expected IP layer attributes.
        
        Returns:
            list[dict]: List of dictionaries representing nodes and edges for visualization (only if save=True).
        
        Example:
            elements = pcap_to_element_converter_timestamp(packets, save=True)

    `run_dash(self)`
    :   Runs the Dash application after validating and setting up required elements.
        This method performs the following steps:
        1. Checks if `self.elements` is not None or empty.
        2. Validates the format of `self.elements` using `self.elements_checker`.
        3. Sets up the Dash application by calling `self.setup_dash`.
        4. Runs the Dash app with debugging enabled.
        Raises:
            ValueError: If `self.elements` is None or empty.
            ValueError: If `self.elements` does not pass the format check.

    `setup_dash(self)`
    :   Initializes and configures the Dash application.
        
        This method creates a Dash app instance, sets its title,
        and sets up the layout and callback functions required for the dashboard.
        
        Args:
            None
        
        Returns:
            None

    `setup_dash_functions(self)`
    :   Sets up Dash callback functions for interactive components in the dashboard.
        This method registers a callback for the Cytoscape graph component to handle node click events.
        When a node is clicked, its information is displayed in the designated output component.
        Callback:
            - Output: Updates the "node-click-output" component's children with node information.
            - Input: Listens for "tapNodeData" events from the "cytoscape-graph" component.
        Returns:
            None

    `setup_dash_layout(self)`
    :   Sets up the Dash application layout for packet flow visualization.
        This method configures the main layout of the Dash app, including:
        - A header displaying "Packet Flow Visualization".
        - A Cytoscape graph for visualizing packet flows, with nodes and edges styled for clarity.
        - An output div for displaying information when a node is clicked.
        The layout uses a force-directed graph ("cose" layout) and applies custom styles for nodes, edges, and background.
        Returns:
            None