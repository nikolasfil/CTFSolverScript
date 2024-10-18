How scripts work :

We make a folder inside app/ctfsolver/ that contains the module we want to run.
Inside the folder app/ctfsolver/scripts/ we create a file with the name of the module we want to shortcut.
and then we add it to the setup.py

```json
entry_points={
        "console_scripts": [
            "folders=ctfsolver.scripts.run_folders:main",
            "run=ctfsolver.scripts.run_solution:main",
        ]
    },
```
