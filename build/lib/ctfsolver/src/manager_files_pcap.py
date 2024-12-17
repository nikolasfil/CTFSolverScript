from pathlib import Path
import inspect
from scapy.all import rdpcap
import os
import ast


class ManagerFilePcap:
    def __init__(self, *args, **kwargs):
        pass

    def initializing_all_ancestors(self, *args, **kwargs):
        """
        Description:
            Initializes all the ancestors of the class
        """

    def pcap_open(self, file=None, save=False):
        """
        Description:
            Open the pcap file with scapy and saves it in self.packets

        Args:
            file (Path, optional): File to open. Defaults to None.
            save (bool, optional): Save the output. Defaults to False.

        """

        if file is None:
            file = self.challenge_file

        self.packets = rdpcap(file.as_posix())

        if save:
            return self.packets
