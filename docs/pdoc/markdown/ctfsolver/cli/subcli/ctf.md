Module ctfsolver.cli.subcli.ctf
===============================

Functions
---------

`automove(checker: bool = <typer.models.OptionInfo object>, verbose: bool = <typer.models.OptionInfo object>)`
:   Automatically move downloaded CTF files to their respective challenge folders.

`create(category: str = <typer.models.OptionInfo object>, site: str = <typer.models.OptionInfo object>, name: str = <typer.models.OptionInfo object>, checker: bool = <typer.models.OptionInfo object>, download: bool = <typer.models.OptionInfo object>, verbose: bool = <typer.models.OptionInfo object>)`
:   Create a new CTF challenge structure.

`find_usage(directory: str = <typer.models.OptionInfo object>)`
:   Find usage of a specific import statement in project files.

`folders()`
:   Create the folder structure as specified by the global configuration.

`init_challenge()`
:   Initialize challenge configuration in the current directory.

`link()`
:   Link CTF folders (implementation TBD).

`show(category: str = <typer.models.OptionInfo object>, site: str = <typer.models.OptionInfo object>)`
:   Navigate CTF categories/sites and list subdirectories.