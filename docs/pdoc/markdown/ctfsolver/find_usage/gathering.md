Module ctfsolver.find_usage.gathering
=====================================

Classes
-------

`Gathering(**kwargs)`
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

    * ctfsolver.src.ctfsolver.CTFSolver
    * ctfsolver.managers.manager_file.ManagerFile
    * ctfsolver.managers.manager_files_pcap.ManagerFilePcap
    * ctfsolver.managers.manager_files_re.ManagerFileRegex
    * ctfsolver.managers.manager_folder.ManagerFolder
    * ctfsolver.managers.manager_functions.ManagerFunction
    * ctfsolver.managers.manager_connections.ManagerConnections
    * ctfsolver.managers.manager_crypto.ManagerCrypto
    * ctfsolver.error.manager_error.ManagerError

    ### Methods

    `another_attempt(self)`
    :

    `ascii_converter(self, bits)`
    :   Convert a string of bits to ASCII characters.
        Input bits should be in multiples of 8 (for standard ASCII).
        Handles padding if needed.

    `ascii_converter1(self, bits: str) ‑> str`
    :

    `ascii_rot(self, text, n)`
    :   Description:
            Rotates the ASCII characters in a string by n positions
        
        Args:
            text (str): The text to rotate
            n (int): The number of positions to rotate

    `attempt_for_loop_subkeys(self)`
    :

    `bits_to_ascii(self, bits)`
    :   Convert a list of bits (ints) to ASCII string.
        Assumes 8 bits per character, MSB first.

    `breakfiles(self, exfiltrated_data)`
    :

    `brute_ascii_rot(self, text, identifier)`
    :   Description:
            Brute forces the rotation of ASCII characters in a string
        
        Args:
            text (str): The text to rotate
            identifier (str): The string to search for in the rotated text
        
        Returns:
            str: The rotated text

    `brute_force(self, encrypted_data)`
    :

    `brute_transpose_find_flag(self, lyrics: str, partial_flag: str, keys: list, verbose: bool = False, wrap: bool = True)`
    :   Description:
            For the lyrics given
        
        Args:
            lyrics (str): Lyrics given
            partial_flag (str): partial flag to look
            verbose (bool, optional): _description_. Defaults to False.
        
        Returns:
            str: possible flag

    `bruteforce(self)`
    :

    `bruteforce_address(self, start=0, number=1000, count=125, verbose=False)`
    :

    `bruteforce_all_lyrics(self, all_lyrics: list, partial_flag: str, keys: list, verbose: bool = False, wrap: bool = True)`
    :

    `bruteforce_key(self, verbose=False)`
    :

    `bruteforce_key_multiprocessing(self, verbose=False)`
    :   Multiprocessing brute-force key search.

    `bruteforcer(self)`
    :

    `bruteforcing(self)`
    :

    `bruteforcing_failed(self)`
    :

    `build_payload(self)`
    :

    `bytes_to_int_array(self, data)`
    :   Convert bytes to array of integers

    `challenge_get_offset_address(self)`
    :

    `check_for_rot(self, text, partial='ecsc')`
    :   Description:
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

    `check_password_time(self, length)`
    :

    `connecting_db(self)`
    :

    `context(self, number)`
    :

    `copy(self, file1, file2)`
    :

    `create_token(self, username)`
    :

    `creating_control_combos(self, start=0, end=1, number=8)`
    :

    `creating_stream(self, packets=None, save=False, return_dict=False)`
    :

    `csend(self, contract: str, fn: str, *args)`
    :

    `current_initiate_connection(self)`
    :

    `custom_init(self)`
    :

    `custom_packet_997_attempt(self)`
    :

    `custom_re_match_base64_string(self, text: str, strict=False) ‑> list[str]`
    :   Description:
        Find the base64 string in the text
        
        Args:
            text (str): Text to search for base64 string
            strict (bool, optional): If True, it will only return the base64 string. Defaults to False.
        
        Returns:
            str: list of Base64 string found in the text

    `custom_stream_extract(self, packets, stream_num=None)`
    :   Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.
        
        Args:
            packets (dict): Dictionary of packets
            stream_num (int): Stream number to extract
        
        Returns:
            dict: Dictionary of packets

    `data_processing(self, data)`
    :

    `de_hexing_flag(self, flag)`
    :

    `dec_file_mes(self, mes, key)`
    :

    `decode_address(self, address_all, start=0, end=None)`
    :   Description:
            Decodes the address of the stack
        
        Args:
            address_all (list): List of addresses
            start (int, optional): Starting position of the address. Defaults to 0.
            end ([type], optional): Ending position of the address. Defaults to None.
        
        Returns:
            bytes: Decoded text of the address

    `decode_hamming74(self, encoded_bits)`
    :   Decode a Hamming (7,4) encoded bit string to ASCII.
        Each 7 bits contain 4 data bits and 3 parity bits.
        Returns ASCII decoded string.

    `decode_manchester(self, encoded_bits)`
    :   Decode Manchester encoded bit string to ASCII.
        Manchester encoding: each bit is two bits:
        '01' -> 0
        '10' -> 1

    `decode_nrz_i(self, bits: str) ‑> str`
    :   Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.

    `decode_nrzi(self, bits: str) ‑> str`
    :   Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.

    `decode_uart(self, encoded_bits, baud_rate=9600, data_bits=8, parity=1, stop_bits=1)`
    :   Decode UART encoded bit string to ASCII.
        Assumes:
        - 1 start bit (0)
        - 8 data bits (LSB first)
        - 1 parity by default
        - 1 stop bit (1)
        encoded_bits is a string of bits representing UART frames concatenated.

    `decoding(self, crypted_dict, data)`
    :

    `decrypt(self, cipher_list, key)`
    :

    `decrypt_password(self, ciphertext, secret_key)`
    :

    `decrypt_payload(self, cipher, payload)`
    :

    `decrypt_string(self, encrypted_base64, key)`
    :

    `decrypting_packet(self)`
    :   Description:
            Challenge specific function

    `decrypting_stream_4(self)`
    :   Description:
            Challenge specific function

    `decrypting_vigenere(self, ciphertext, key)`
    :

    `demarshalling(self)`
    :   Description:
            This function is used to demarshall the compressed data and display the disassembled code.
            Challenge specific function

    `deobfuscation(self)`
    :

    `derive_key_and_iv(self, password, salt, key_length, iv_length)`
    :

    `des_key_generator(self)`
    :   Generator for all possible 8-byte DES keys.
        DES uses a 56-bit key space, padded to 8 bytes.

    `dictionary_analysis(self, lyrics)`
    :

    `differ(self)`
    :

    `download_images(self, name)`
    :

    `downloading(self)`
    :

    `dynamic_xor_decrypt(self, plaintext, text_key)`
    :

    `dynamic_xor_encrypt(self, plaintext, text_key)`
    :

    `emilia_main(self)`
    :

    `encode_nrzi(self, bits: str, verbose=False) ‑> str`
    :   Decode NRZ-I (Non-Return-to-Zero Inverted) encoded bits.
        In NRZ-I, a transition (0 to 1 or 1 to 0) represents a 1,
        and no transition represents a 0.

    `encrypt(self, plaintext, key)`
    :

    `evtx_open(self, file, func, *args, **kwargs)`
    :

    `exec_fmt(self, payload)`
    :

    `exec_func(self, payload)`
    :

    `exploit(self)`
    :

    `exploit_development(self, i, letter)`
    :

    `exploitation(self)`
    :

    `extract_exif(self, file_path)`
    :   Description:
            Extracts EXIF data from a file
        
        Args:
            file_path (str): The path to the file
        
        Returns:
            dict: The EXIF data

    `extract_files_from_binary(self, filepath)`
    :

    `extract_macros_from_file(self, ods_file, file_name)`
    :   Extracts content from a specific file inside the ODS archive.
        
        Args:
            ods_file (str): Path to the ODS file.
            file_name (str): Name of the file inside the archive to extract.
        
        Returns:
            str: The content of the specified file.

    `extract_macros_from_ods(self, ods_file)`
    :   Attempts to extract macros from various files in the ODS archive.
        
        Args:
            ods_file (str): Path to the ODS file.
        
        Returns:
            str: Extracted macros or debug information.

    `extract_macros_from_ods_initial(self, ods_file=None)`
    :   Extracts macros from an ODS file.
        
        Args:
            ods_file (str): Path to the ODS file.
        
        Returns:
            str: Extracted macros, if any, as plain XML text.

    `extract_macros_with_odfpy(self, ods_file, files)`
    :

    `extract_printable_with_spaces(self, text)`
    :

    `extract_skew1_bootkey_piece(self, hive_path: str) ‑> str`
    :

    `find_collision(self, target_hash, max_length=10, prefix='', suffix='', lengthy=False)`
    :

    `find_invpow(self, x, n)`
    :   Finds the integer component of the n'th root of x,
        an integer such that y ** n <= x < (y + 1) ** n.

    `find_offset(self, pattern, n=8)`
    :   Finds the offset of a given pattern in the cyclic pattern.
        
        Args:
            pattern (str): The pattern to find the offset for.
            n (int): The number of unique characters in the pattern.
        
        Returns:
            int: The offset of the pattern.

    `finding_next_prime(self, number, n=None)`
    :

    `from_hex(self, data)`
    :

    `gathering(self)`
    :

    `generate_cipher(self, aes_key, iv)`
    :

    `generate_pattern(self, length=1, n=8)`
    :   Generates a cyclic pattern of a given length.
        
        Args:
            length (int): The length of the pattern to generate.
            n (int): The number of unique characters in the pattern.
        
        Returns:
            str: The generated cyclic pattern.

    `generate_payload(self, attacker_url)`
    :

    `generate_url(self, attacker_url, payload)`
    :   Description:
            Generate a URL with the given attacker URL and payload.
        
        Args:
            attacker_url (_type_): _description_
            payload (_type_): _description_
        
        Returns:
            _type_: _description_

    `generating(self)`
    :

    `generator(self, g, x, p)`
    :

    `get_address(self)`
    :

    `get_attributes(self, variable)`
    :   Get all attributes of a variable

    `get_cell_size(self)`
    :

    `get_elf_function_address(self, function)`
    :   Description:

    `get_flag_length(self)`
    :

    `get_functions(self, variable, under=False)`
    :   Get all functions of a variable

    `get_instruments(self)`
    :   Returns a list of instruments in the MIDI file.

    `get_message(self)`
    :

    `get_online_passwords(self)`
    :

    `get_output_variables(self)`
    :

    `get_registers(self, address, count=125)`
    :

    `get_request(self, path)`
    :

    `get_scapy_tcp_stream(self, nunber: int)`
    :

    `get_tcp_stream(self, number)`
    :

    `get_welcome_message(self)`
    :

    `getting_base64(self)`
    :

    `getting_round(self)`
    :

    `hash_pw(self, pw_str)`
    :

    `hex_to_bytes_le(self, hex_val, size)`
    :

    `hex_to_string(self, hex_string)`
    :   Description: Convert hex string to ascii string
        
        Analytical:
        - Split the hex string by space
        - Convert each hex value to ascii character
        - Join the ascii characters to form the ascii string
        
        Args:
            hex_string (str): Hex string to convert to ascii
        
        Returns:
            str: Ascii string

    `hexdump_to_binary(self, hexdump_file, binary_file)`
    :

    `hive_solution(self)`
    :

    `init_some_values(self)`
    :

    `initialize_values(self)`
    :

    `int_array_to_bytes(self, data)`
    :   Convert array of integers to bytes

    `interacting_with_binary(self)`
    :

    `interacting_with_mcp(self)`
    :

    `interactive(self)`
    :   Descrption : Start an interactive session
        Parameters : None
        Returns : None

    `is_prime(self, p)`
    :

    `juilius_decrypt(self, msg, shift)`
    :

    `known_colissions(self)`
    :

    `length_find(self)`
    :

    `list_all_files(self, ods_file)`
    :   Lists all files in the ODS archive for manual inspection.
        
        Args:
            ods_file (str): Path to the ODS file.
        
        Returns:
            list: A list of files inside the ODS archive.

    `load_compressed_data(self)`
    :   Description:
            Challenge specific function to load the compressed data

    `load_lyrics(self)`
    :

    `load_master_key(self)`
    :

    `load_shellcode(self)`
    :

    `local_evtx_analysis(self, file)`
    :

    `local_exploitation(self)`
    :   Performs local exploitation to find the offset.
        
        Returns:
            int: The offset found from the local exploitation.

    `local_preparations(self)`
    :

    `local_run(self)`
    :

    `local_searching_file(self, file, *args, **kwargs)`
    :

    `look_all_subkeys(self)`
    :

    `looper(self)`
    :

    `lyric_transformation(self, lyrics)`
    :

    `lyric_transpose(self, lyrics, offset, wrap=True)`
    :

    `lyrics_all(self)`
    :   Description:
            This function generates all possible combinations of lyrics transformations
            based on the provided replace_combos and control_combos.
            It uses itertools.product to create combinations of the specified number
            of transformations, allowing for flexible lyric manipulation.
        Returns:
            list: A list of transformed lyrics combinations.

    `lyrics_transformation(self, lyrics, replace_combos, control_combos=None)`
    :

    `main_multi_process(self)`
    :

    `md5_hash(self, s)`
    :

    `menu_handler(self, verbose=False)`
    :

    `modify_picture(self)`
    :

    `music21_analysis(self)`
    :

    `music21_note_analysis(self)`
    :

    `mutate_key(self, buf: bytearray, key: bytes) ‑> bytearray`
    :

    `nrzi_formater(self, bits: list)`
    :

    `nrzi_formater_for_rest(self, bits: list)`
    :

    `nrzi_to_ascii(self, bits)`
    :

    `open_file(self)`
    :

    `oracle_encrypt(self, pt_hex)`
    :

    `parse_csr(self)`
    :

    `payload_maker(self, password, number)`
    :

    `pickle_load_data(self, filename: str, folder: str = 'data') ‑> <built-in function any>`
    :   Description:
            Load data from a pickle file
        
        Args:
            filename (str): Filename to load the data from
            folder (str, optional): Folder name to find the file to load the data from. Defaults to "data".
        
        Returns:
            any: Data loaded from pickle

    `pickle_save_data(self, data: <built-in function any>, filename: str, folder: str = 'data') ‑> None`
    :   Description:
            Save data to a pickle file
        
        Args:
            data (any): data to write to the pickle file. Can be anything
            filename (str): Filename to save
            folder (str, optional): Folder name inside the ctf folder. Defaults to "data".
        
        Returns:
            None

    `play_game(self)`
    :

    `play_round(self)`
    :

    `plc_initiate_connection(self)`
    :

    `plc_work(self, solution, plc)`
    :

    `pollute(self, base_url)`
    :

    `position_cipher(self, text: str, keys: list)`
    :   Description:
            This function takes a text and a list of keys, and returns a new string
            where each character in the text is replaced by the character at the
            corresponding index in the keys list. If the index exceeds the length of
            the text, it wraps around using modulo operation.
        Args:
            text (str): The input text to be transformed.
            keys (list): A list of integers representing the positions in the text.
        Returns:
            str: A new string formed by replacing characters in the text based on the keys.

    `preparing_dictionary(self)`
    :   This method is not used in the current solution.
        It can be implemented if needed for future enhancements.

    `print_dictionary(self, d)`
    :

    `print_to_File(self, data, verbose=False, file_name='output.txt')`
    :

    `pyshark_extrac_tcp_stream_numbers(self, pcap_file)`
    :   Description:
            Extracts the tcp stream numbers from the pcap
        
        Args:
            pcap_file (str): Path to the pcap file.
        
        Returns:
            dict: Dictionary of session indexes

    `pyshark_extract_tcp_streams(self, pcap_file, stream_num)`
    :

    `random_flouri_generator(self, number=None)`
    :

    `read_address_positions(self, positions)`
    :   Reads the address of the stack
        
        Args:
            positions (int): Number of positions to read
        
        Returns:
            list: List of addresses

    `read_json(self, filename)`
    :

    `reassemblying_dns(self, packets=None)`
    :

    `reconstructing_url(self)`
    :

    `recover_skew1_cell_hex(self, cell_size, cell_data)`
    :   Recover the Skew1 part of the Windows BootKey as a continuous hex string.
        
        Args:
            cell_size (int): The size of the registry cell (including size bytes and data).
            cell_data (bytes): The raw bytes of the cell data including the Skew1 Class Name/Attribute.
        
        Returns:
            str: The continuous hex string in the format ECSC{...}

    `regexp(self, file_content)`
    :

    `remote_exploitation(self, payload)`
    :   Performs remote exploitation using the given payload.
        
        Args:
            payload (bytes): The payload to use for remote exploitation.

    `rot(self, text, shift)`
    :   Applies the ROT47 cipher to the given text with the specified shift.
        
        Args:
            text (str): The input text.
            shift (int): The ROT47 shift amount.
        
        Returns:
            str: The transformed text.

    `rot_bruteforce(self, crypted_text, known_text, max_shift=94)`
    :   Brute forces ROT47 shifts to find the one that contains the known text.
        
        Args:
            crypted_text (str): The encrypted text.
            known_text (str): The known plaintext to look for.
            max_shift (int): The maximum shift to attempt (ROT47 has 94 shifts).
        
        Returns:
            int: The shift that contains the known text, or -1 if not found.

    `rot_char(self, c, shift)`
    :   Rotates a single character using the ROT47 cipher.
        
        Args:
            c (str): The input character.
            shift (int): The ROT47 shift amount.
        
        Returns:
            str: The rotated character.

    `run(self)`
    :

    `saving_requests(self)`
    :   Save the requests made during the challenge to a file.
        This can help in debugging or understanding the flow of the challenge.

    `saving_stream_4_encrypted_bytes(self)`
    :   Description:
            Challenge specific function

    `saving_to_json(self, crypted_dict)`
    :

    `saving_xml(self, log_file, file, display=False)`
    :

    `searching_packets(self, packets, text)`
    :

    `searching_records(self, log_file, func, *args, **kwargs)`
    :

    `send_file(self, file)`
    :

    `send_to_bot(self, payload_url)`
    :   Description:
            Send the payload URL to the bot.
        
        Args:
            payload_url (_type_): _description_
        
        Returns:
            _type_: _description_

    `sending_request(self, exploit=None, verbose=False)`
    :

    `setup(self)`
    :

    `setup_request(self)`
    :

    `setup_sse(self, sse_url)`
    :

    `simple_payload_send(self, payload, lines=1)`
    :   Description:
            Sends a simple payload to the connection
        
        Args:
            payload (str): Payload to send
            lines (int, optional): Number of lines to receive. Defaults to 1.
        
        Returns:
            bytes: Output of the connection

    `simulate_ansi_typing(self, text, escape_codes=True)`
    :

    `skew_get_value(self)`
    :

    `smart_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False, save: bool = False, filename_save: str = 'packets.pickle', folder_save: str = 'data')`
    :   Description:
            Extracts the packets from the pcap file and saves them as a dictionary.
            If the file already exists, it loads the file.
        
        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
            raw (bool, optional): Option to return the raw packets. Defaults to False.
            save (bool, optional): Option to load saved file . Defaults to False.
            filename_save (str, optional): Filename to save the packets if enabled. Defaults to "packets.pickle".
            folder_save (str, optional): Folder to save the filename if save is enabled. Defaults to "data".

    `smarter_bruteforcer(self)`
    :   Check the first letter first, and then continue

    `snap_initiate_connection(self)`
    :

    `socket_initiate_connection(self)`
    :

    `solve(self)`
    :

    `solve_challenge(self)`
    :   Main function to solve the challenge

    `solve_equations(self)`
    :

    `sorting_results(self, results)`
    :

    `ssh_connect(self, **kwargs)`
    :   Descrption : Establish SSH connection
        Parameters :
            - user : username
            - host : hostname
            - port : port number
            - password : password
        
        Returns : None

    `str_xor(self, secret, key)`
    :

    `stream_identifier(self, pkt)`
    :

    `test_letter(self, password)`
    :

    `testin_streams(self)`
    :

    `testing_ansii_escape(self)`
    :

    `textFromPDF(self, file=None)`
    :   Extracts text from a PDF file.
        
        Args:
            file (str): Path to the PDF file. Defaults to the challenge file.
        
        Returns:
            str: The extracted text.

    `to_hex(self, data)`
    :

    `tools_result(self)`
    :

    `translated(self)`
    :

    `try_catch(self, callback)`
    :

    `try_key(self, candidate: str)`
    :

    `trying_to_exploit_ods(self)`
    :

    `unified_extract_packets(self, pcap_file, pcap_function: str, raw: bool = False)`
    :   Description:
            Extracts the packets from the pcap file and saves them as a numbered dictionary.
            Can use either scapy or pyshark to extract the packets.
        
        Args:
            pcap_file (str): Path to the pcap file.
            pcap_function (str): Function to use to extract the packets.[scapy, pyshark]
        
        Returns:
            dict: Dictionary of packets

    `validate_flag(self)`
    :

    `verify_js_reconstructed(self)`
    :

    `xor_bytes(self, a, b)`
    :

    `xor_decrypt(self, key_bytes: bytes, input_bytes: bytes) ‑> bytes`
    :

    `xor_function_dec(self, given_string, length)`
    :