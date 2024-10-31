from pathlib import Path
import inspect
from scapy.all import rdpcap


class ManagerFile:
    def __init__(self, *args, **kwargs):
        self.Path = Path
        self.get_parent()
        self.file = kwargs.get("file")
        self.get_challenge_file()
        self.debug = kwargs.get("debug", False)

    def get_parent(self):
        """
        Description:
        Create object for the class for parent, payloads, data and files folder paths for the challenge
        """
        self.parent = None
        self.folder_payloads = None
        self.folder_data = None
        self.folder_files = None

        self.file_called_frame = inspect.stack()
        self.file_called_path = Path(self.file_called_frame[-1].filename)
        self.parent = Path(self.file_called_path).parent

        if self.parent.name == "payloads":
            self.folder_payloads = self.parent
            self.parent = self.parent.parent
            
        self.folder_data = Path(self.parent, "data")
        self.folder_files = Path(self.parent, "files")
        self.folder_payloads = Path(self.parent, "payloads")

    def create_parent_folder(self):
        """ """

        self.folder_data = Path(self.parent, "data")
        self.folder_files = Path(self.parent, "files")
        self.folder_payloads = Path(self.parent, "payloads")

        folder_list = [
            self.folder_payloads,
            self.folder_data,
            self.folder_files,
        ]

        for folder in folder_list:
            if not folder.exists():
                folder.mkdir()

    def prepare_space(self, files=None, folder=None, test_text="picoCTF{test}"):
        """
        Description:
        Prepare the space for the challenge by creating the folders if they don't exist
        """
        files = files if files else []
        folder = folder if folder else self.folder_files

        for file in files:
            if not Path(folder, file).exists():
                with open(Path(folder, file), "w") as f:
                    f.write(test_text)

    def get_challenge_file(self):
        if self.file and self.folder_data:
            self.challenge_file = Path(self.folder_files, self.file)
        elif not self.folder_data:
            if self.debug:
                print("Data folder not found")

    def search_for_pattern_in_file(
        self, file, func=None, display=False, save=False, *args, **kwargs
    ):
        """
        Description:
        Search for a pattern in the file and return the output

        Args:
            file (str): File to search for the pattern
            func (function, optional): Function to search for the pattern. Defaults to None.
            display (bool, optional): Display the output. Defaults to False.
            save (bool, optional): Save the output. Defaults to False.

        Returns:
            list: List of output if save is True

        """
        if save:
            output = []
        if func is None:
            return None

        with open(file, "r") as f:
            for line in f:
                result = func(line, *args, **kwargs)
                if result is not None:
                    if display:
                        print(result)
                    if save:
                        output.extend(result)
        if save:
            return output

    def exec_on_files(self, folder, func, *args, **kwargs):
        """
        Description:
        Execute a function on all the files in the folder with the arguments provided

        Args:
            folder (str): Folder to execute the function
            func (function): Function to execute

        Returns:
            list: List of output of the function
        """

        save = kwargs.get("save", False)
        display = kwargs.get("display", False)
        if save:
            output = []
        for file in folder.iterdir():
            out = func(file, *args, **kwargs)
            if save and out is not None:
                output.extend(out)
            if display and out is not None:
                print(out)
        if save:
            return output

    def pcap_open(self, file=None):
        """
        Description:
        Open the pcap file with scapy and saves it in self.packets
        """

        if not file:
            file = self.challenge_file

        self.packets = rdpcap(file.as_posix())
