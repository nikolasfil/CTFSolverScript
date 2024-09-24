from pathlib import Path
import pwn
import inspect


class CTFSolver:
    def __init__(self, *args, **kwargs) -> None:
        self.pwn = pwn
        self.get_parent()
        self.connect_to_challenge(kwargs)

    def connect_to_challenge(self, kwargs):
        self.file = kwargs.get("file")
        self.get_challenge_file()
        self.url = kwargs.get("url")
        self.port = kwargs.get("port")
        self.conn_type = kwargs.get("conn")
        self.conn = None
        self.connect(self.conn_type)

    def get_parent(self):
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

    def get_challenge_file(self):
        if self.file and self.folder_data:
            self.challenge_file = Path(self.folder_files, self.file)
        elif not self.folder_data:
            print("Data folder not found")

    def connect(self, *args, **kwargs) -> None:
        if self.conn_type == "remote" and self.url and self.port:
            self.conn = pwn.remote(self.url, self.port)
        elif self.conn_type == "local" and self.file:
            self.conn = pwn.process(str(self.challenge_file))

    def main(self):
        pass

    # def __del__(self):
    #     self.conn.close()

    # def __exit__(self, exc_type, exc_value, traceback):
    #     self.conn.close()

    # Todo
    # Add cryptography solutions
    # Add web solutions


if __name__ == "__main__":
    s = CTFSolver(conn="remote")
    s.main()
