# Architecture Tree

The following is the directory structure of the `ctfsolver` application, illustrating its modular design and organization:

```
./app/ctfsolver
├── cli
│   ├── __init__.py
│   ├── main.py
│   └── subcli
│       ├── ctf.py
│       ├── __init__.py
│       └── venv.py
├── config
│   ├── challenge_config.py
│   ├── config_template.json
│   ├── global_config.py
│   ├── __init__.py
│   └── __main__.py
├── data
│   ├── challenge_info_template.json
│   └── config_template.json
├── error
│   ├── __init__.py
│   └── manager_error.py
├── feature_test
│   ├── attempt_at_pcap.py
│   ├── dash_test.py
│   ├── __init__.py
│   ├── manager_graphs.py
│   ├── pyvis_class_test.py
│   ├── pyvis_test.py
│   └── testing_files.py
├── find_usage
│   ├── function_definition_class.py
│   ├── gathering.py
│   ├── __init__.py
│   ├── __main__.py
│   └── manager_gathering.py
├── folders
│   ├── finding_writeups.py
│   ├── __init__.py
│   ├── link_ctf_folders.py
│   └── __main__.py
├── forensics
│   ├── __init__.py
│   └── manager_dash.py
├── __init__.py
├── managers
│   ├── __init__.py
│   ├── manager_class.py
│   ├── manager_connections.py
│   ├── manager_crypto.py
│   ├── manager_file.py
│   ├── manager_files_evtx.py
│   ├── manager_files_pcap.py
│   ├── manager_files_re.py
│   ├── manager_folder.py
│   └── manager_functions.py
├── scripts
│   ├── clean_folders
│   │   ├── __init__.py
│   │   └── __main__.py
│   ├── __init__.py
│   ├── __main__.py
│   ├── run_clean_folders.py
│   ├── run_folders.py
│   └── run_solution.py
├── src
│   ├── ctfsolver.py
│   ├── __init__.py
│   ├── position_cipher_functions.py
│   └── README.md
├── template
│   ├── gathering_template.py
│   ├── __init__.py
│   ├── __main__.py
│   └── solution_template.py
├── test
│   └── __init__.py
└── venv
    ├── __init__.py
    ├── main.py
    ├── manager_venv.py
    └── testing
        ├── __init__.py
        └── main.py
```
