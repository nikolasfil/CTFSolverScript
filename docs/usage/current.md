## Current usage of the package

```bash
find . -type d \( -name "app_venv" -o -name "venv" \) -prune -o -type f -exec grep -l "from ctfsolver import CTFSolver" {} +
```

```
./Categories/Forensics/picoCTF/Blast_from_the_past_picoCTF_2024/payloads/solution.py
./Categories/Forensics/picoCTF/endianness_v2_picoCTF_2024/payloads/solution.py
./Categories/Forensics/picoCTF/PcapPoisoning/payloads/solution.py
./Categories/Forensics/picoCTF/hideme/payloads/solution.py
./Categories/General/picoCTF/SansAlpha/payloads/solution.py
./Categories/Binary/picoCTF/heap_0_picoCTF_2024/payloads/solution.py
./Categories/Binary/picoCTF/format_string_1/payloads/solution.py
./Categories/Binary/picoCTF/format_string_2/payloads/solution.py
./Categories/Binary/picoCTF/format_string_3/payloads/solution.py
./Categories/Binary/picoCTF/heap_1/payloads/solution.py
./Categories/Binary/picoCTF/heap_2/payloads/solution.py
./Categories/Binary/picoCTF/heap_3/payloads/solution.py
./Categories/Binary/picoCTF/Picker_4/payloads/solution.py
./Categories/Cryptography/picoCTF/ReadMyCert/payloads/solution.py
./Categories/Cryptography/picoCTF/basic_mod1/payloads/solution.py
./Categories/Reverse_Engineering/picoCTF/Picker_1/payloads/solution.py
./Categories/Reverse_Engineering/picoCTF/Picker_2/payloads/solution.py
./Categories/Reverse_Engineering/picoCTF/Picker_3/payloads/solution.py
```

Finding ctf folders that don't have the universal folder structure

```bash
find . -mindepth 4 -maxdepth 4 -type d -not \( -path "*/.git*" -o -path "*/venv*" -o -path "*/app_venv*" \)
```
