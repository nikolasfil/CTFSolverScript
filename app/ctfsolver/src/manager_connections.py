import pwn


class ManagerConnections:
    def __init__(self, *args, **kwargs) -> None:
        self.pwn = pwn

        self.url = kwargs.get("url")
        self.port = kwargs.get("port")
        self.conn_type = kwargs.get("conn")
        self.conn = None
        self.menu_num = None
        self.menu_text = None
        self.debug = kwargs.get("debug", False)
        # self.initiate_connection()

    def initiate_connection(self):
        self.connect(self.conn_type)

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
        """
        Description:
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
        """
        if save:
            result = []
        if menu_num is None and self.menu_num is None:
            raise ValueError("Menu number not provided")

        if menu_num:
            self.menu_num = menu_num

        if menu_text is None and self.menu_text is None:
            raise ValueError("Menu text not provided")

        if menu_text:
            self.menu_text = menu_text

        out = self.recv_menu(number=self.menu_num, display=display, save=save)
        if save:
            result.extend(out)

        out = self.conn.recvuntil(self.menu_text.encode())
        if save:
            result.append(out)

        if display:
            print(out)

        self.conn.sendline(str(choice).encode())

        if save:
            return result
