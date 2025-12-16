Module ctfsolver.venv.testing.main
==================================

Classes
-------

`ManagerVenv()`
:   Cross-platform venv manager that can create, link, resolve and operate inside virtual environments
    without in-process "activation". Instead, it uses the venv's interpreter directly.
    
    Conventions:
      - Global root for venvs is taken from CONFIG["directories"]["venvs"] (preferred),
        else $CTFSOLVER_VENVS_HOME, else POSIX: ~/.local/share/ctfsolver/venvs,
        Windows: %APPDATA%\ctfsolver\venvs
      - Project shortcut: `.venv` (symlink/junction) preferred; fallback `.venv.link` text file
        containing absolute path to the real venv directory.
    
    Public methods cover:
      - create (backend: stdlib venv or virtualenv)
      - link/unlink shortcuts
      - resolve_for current project
      - activation_command printer
      - run_in (execute using the venv's python)
      - detect_venvs, export_lockfiles (pip freeze + pipdeptree)
      - transfer, delete, list_venvs

    ### Static methods

    `summarize(info: VenvInfo) ‑> str`
    :

    ### Methods

    `activation_command(self, venv: VenvInfo, shell: Optional[str] = None) ‑> str`
    :   Return the shell command string to activate the venv. Does not execute it.
        shell: one of {'bash','zsh','fish','pwsh','cmd'} or None to auto-detect.

    `check_venv_dir(self)`
    :

    `create(self, name: str, python: Optional[Path] = None, in_project: bool = False, project_dir: Optional[Path] = None, backend: str = 'venv', with_pip: bool = True) ‑> ctfsolver.venv.testing.main.VenvInfo`
    :   Create a venv using stdlib venv or virtualenv, return VenvInfo and link to project_dir if provided.

    `create_and_link_current(self, name: str, *, python: Optional[Path] = None, backend: str = 'venv', with_pip: bool = True, project_dir: Optional[Path] = None) ‑> ctfsolver.venv.testing.main.VenvInfo`
    :   Create a global venv and link it to the given project (default: CWD).

    `delete(self, venv_path: Path, force: bool = False) ‑> None`
    :   Delete a venv directory recursively.

    `detect_venvs(self, root: Path, recursive: bool = True) ‑> Iterable[pathlib._local.Path]`
    :   Yield venv directories under root.

    `export_lockfiles(self, venv_path: Path, out_dir: Path) ‑> tuple[pathlib._local.Path, pathlib._local.Path]`
    :   Create requirements.txt and pipdeptree.txt for venv.
        If pipdeptree is not installed, install temporarily and remove afterwards.

    `link(self, project_dir: Path, venv_path: Path) ‑> None`
    :   Create a project shortcut to an existing venv.
        Prefer a symlink (POSIX) or junction/symlink (Windows). Fallback to .venv.link text file.

    `list_venvs(self) ‑> list[ctfsolver.venv.testing.main.VenvInfo]`
    :   List venvs in the global directory.

    `resolve_for(self, project_dir: Path) ‑> ctfsolver.venv.testing.main.VenvInfo | None`
    :   Resolve VenvInfo for a project directory, if a shortcut/link exists.

    `run_in(self, venv_path: Path, args: Sequence[str], *, cwd: Optional[Path] = None, env: Optional[dict[str, str]] = None, check: bool = True, capture_output: bool = False) ‑> subprocess.CompletedProcess`
    :   Execute a command using the venv's python interpreter: python -m <module> ... or arbitrary script.
        If args[0] == '-m', we run 'python -m ...'; otherwise we execute the given argv via the venv's python.

    `transfer(self, venv_path: Path, dest_root: Optional[Path] = None, move: bool = True) ‑> pathlib._local.Path`
    :   Move or copy a venv to the global store (or a custom root).
        Returns the new path.

    `unlink(self, project_dir: Path) ‑> None`
    :

`VenvInfo(name: str, path: Path, python: Path, platform: str, created_at: float)`
:   VenvInfo(name: 'str', path: 'Path', python: 'Path', platform: 'str', created_at: 'float')

    ### Instance variables

    `created_at: float`
    :   The type of the None singleton.

    `name: str`
    :   The type of the None singleton.

    `path: pathlib._local.Path`
    :   The type of the None singleton.

    `platform: str`
    :   The type of the None singleton.

    `python: pathlib._local.Path`
    :   The type of the None singleton.