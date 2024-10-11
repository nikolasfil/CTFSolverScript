from pathlib import Path
import pwn
import inspect


class CTFSolver:
    def __init__(self, *args, **kwargs) -> None:
        self.pwn = pwn
        self.get_parent()

        self.file = kwargs.get("file")
        self.get_challenge_file()
        self.url = kwargs.get("url")
        self.port = kwargs.get("port")
        self.conn_type = kwargs.get("conn")
        self.conn = None
        self.menu_num = None
        self.menu_text = None
        # self.initiate_connection()

    def initiate_connection(self):
        self.connect(self.conn_type)

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
            print("Data folder not found")

    def connect(self, *args, **kwargs) -> None:
        if self.conn_type == "remote" and self.url and self.port:
            self.conn = pwn.remote(self.url, self.port)
        elif self.conn_type == "local" and self.file:
            self.conn = pwn.process(str(self.challenge_file))

    def recv_menu(self, number=1, display=False, save=False):
        if save:
            result = []
        for _ in range(number):
            out = self.conn.recvline()
            if display:
                print(out)
            if save:
                result.append(out)
        if save:
            return result

    def send_menu(
        self, choice, menu_num=None, menu_text=None, display=False, save=False
    ):
        if (not menu_num and not self.menu_num) or (not self.menu_num):
            return
        if menu_num:
            self.menu_num = menu_num

        if (not menu_text and not self.menu_text) or (not self.menu_text):
            return
        if menu_text:
            self.menu_text = menu_text

        self.recv_menu(number=self.menu_num, display=display, save=save)

        out = self.conn.recvuntil(self.menu_text.encode())
        if display:
            print(out)
        self.conn.sendline(str(choice).encode())

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
