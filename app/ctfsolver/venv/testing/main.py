from __future__ import annotations

import os
import sys
import json
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

from ctfsolver.config import CONFIG

try:
    # Optional third-party creator
    from virtualenv import cli_run as virtualenv_cli_run  # type: ignore

    _HAS_VIRTUALENV = True
except Exception:
    _HAS_VIRTUALENV = False

import venv as stdlib_venv


@dataclass(frozen=True)
class VenvInfo:
    name: str
    path: Path
    python: Path
    platform: str  # 'posix' | 'windows'
    created_at: float


class ManagerVenv:
    """
    Cross-platform venv manager that can create, link, resolve and operate inside virtual environments
    without in-process "activation". Instead, it uses the venv's interpreter directly.

    Conventions:
      - Global root for venvs is taken from CONFIG["directories"]["venvs"] (preferred),
        else $CTFSOLVER_VENVS_HOME, else POSIX: ~/.local/share/ctfsolver/venvs,
        Windows: %APPDATA%\\ctfsolver\\venvs
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
    """

    def __init__(self):
        self.venv_dir: Optional[Path] = self._init_global_dir()
        self.venv: Optional[VenvInfo] = None
        self.check_venv_dir()

    # --- Template-required method -------------------------------------------------
    def check_venv_dir(self):
        if not self.venv_dir:
            raise ValueError("Virtual environment directory is not set.")

    # --- Setup helpers ------------------------------------------------------------
    @staticmethod
    def _is_windows() -> bool:

        return os.name == "nt"

    def _init_global_dir(self) -> Path:
        # Priority: CONFIG -> env -> platform defaults
        cfg_dir = (CONFIG["directories"] or {}).get("venvs", None)
        if cfg_dir:
            return Path(cfg_dir).expanduser()

    # --- Paths & shortcuts --------------------------------------------------------
    @staticmethod
    def _venv_python_path(venv_path: Path) -> Path:
        if os.name == "nt":
            return venv_path / "Scripts" / "python.exe"
        else:
            return venv_path / "bin" / "python"

    @staticmethod
    def _looks_like_venv(path: Path) -> bool:
        if not path.is_dir():
            return False
        pyvenv = path / "pyvenv.cfg"
        act_posix = path / "bin" / "activate"
        act_win = path / "Scripts" / "activate"
        return pyvenv.exists() and (act_posix.exists() or act_win.exists())

    @staticmethod
    def _shortcut_path(project_dir: Path) -> Path:
        # ! ╭─────────────────╮
        # ! │ NEEDS ATTENTION │
        # ! ╰─────────────────╯
        return project_dir / ".venv"

    @staticmethod
    def _linkfile_path(project_dir: Path) -> Path:
        return project_dir / ".venv.link"

    def link(self, project_dir: Path, venv_path: Path) -> None:
        """
        Create a project shortcut to an existing venv.
        Prefer a symlink (POSIX) or junction/symlink (Windows). Fallback to .venv.link text file.
        """
        project_dir = project_dir.resolve()
        venv_path = venv_path.resolve()
        if not self._looks_like_venv(venv_path):
            raise ValueError(f"Not a valid venv: {venv_path}")

        link_target = self._shortcut_path(project_dir)

        # Clean previous
        if link_target.exists() or link_target.is_symlink():
            if link_target.is_dir() and not link_target.is_symlink():
                shutil.rmtree(link_target)
            else:
                link_target.unlink(missing_ok=True)

        try:
            if self._is_windows():
                # Try directory symlink; if not permitted, try junction via mklink /J (needs shell).
                try:
                    link_target.symlink_to(venv_path, target_is_directory=True)
                except OSError:
                    # Junction fallback
                    subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(link_target), str(venv_path)],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
            else:
                link_target.symlink_to(venv_path, target_is_directory=True)
        except Exception:
            # Fallback: .venv.link file
            self._linkfile_path(project_dir).write_text(
                str(venv_path), encoding="utf-8"
            )

    def unlink(self, project_dir: Path) -> None:
        sp = self._shortcut_path(project_dir)
        lp = self._linkfile_path(project_dir)
        if sp.exists() or sp.is_symlink():
            if sp.is_dir() and not sp.is_symlink():
                shutil.rmtree(sp)
            else:
                sp.unlink(missing_ok=True)
        if lp.exists():
            lp.unlink()

    def _resolve_link(self, project_dir: Path) -> Optional[Path]:
        sp = self._shortcut_path(project_dir)
        lp = self._linkfile_path(project_dir)
        if sp.exists():
            try:
                return sp.resolve()
            except Exception:
                pass
        if lp.exists():
            target = Path(lp.read_text(encoding="utf-8").strip())
            if target.exists():
                return target.resolve()
        return None

    def resolve_for(self, project_dir: Path) -> Optional[VenvInfo]:
        """
        Resolve VenvInfo for a project directory, if a shortcut/link exists.
        """
        venv_path = self._resolve_link(project_dir.resolve())
        if not venv_path:
            return None
        py = self._venv_python_path(venv_path)
        if not py.exists():
            return None
        return VenvInfo(
            name=venv_path.name,
            path=venv_path,
            python=py,
            platform="windows" if self._is_windows() else "posix",
            created_at=venv_path.stat().st_ctime,
        )

    # --- Creation -----------------------------------------------------------------
    def create(
        self,
        name: str,
        python: Optional[Path] = None,
        in_project: bool = False,
        project_dir: Optional[Path] = None,
        backend: str = "venv",  # 'venv' | 'virtualenv'
        with_pip: bool = True,
    ) -> VenvInfo:
        """
        Create a venv using stdlib venv or virtualenv, return VenvInfo and link to project_dir if provided.
        """
        self.check_venv_dir()

        if in_project:
            if not project_dir:
                project_dir = Path.cwd()
            venv_path = project_dir / ".venv.local"
        else:
            venv_path = self.venv_dir / name  # type: ignore[operator]

        venv_path = venv_path.resolve()
        venv_path.parent.mkdir(parents=True, exist_ok=True)

        if venv_path.exists():
            raise FileExistsError(f"Venv already exists: {venv_path}")

        if backend not in {"venv", "virtualenv"}:
            raise ValueError("backend must be 'venv' or 'virtualenv'")

        if backend == "virtualenv":
            if not _HAS_VIRTUALENV:
                raise RuntimeError(
                    "virtualenv backend requested but 'virtualenv' is not installed."
                )
            args = [str(venv_path)]
            if python:
                args = ["-p", str(python)] + args
            virtualenv_cli_run(args)  # raises on failure
        else:
            # stdlib venv
            builder = stdlib_venv.EnvBuilder(
                with_pip=with_pip, clear=False, symlinks=True, upgrade=False
            )
            if python and python != Path(sys.executable):
                # Spawn the requested interpreter to create the venv
                cmd = [str(python), "-m", "venv", str(venv_path)]
                if with_pip:
                    cmd.append("--with-pip")
                subprocess.run(cmd, check=True)
            else:
                builder.create(str(venv_path))

        py = self._venv_python_path(venv_path)
        if not py.exists():
            raise RuntimeError(f"Venv created but interpreter not found at: {py}")

        info = VenvInfo(
            name=venv_path.name,
            path=venv_path,
            python=py,
            platform="windows" if self._is_windows() else "posix",
            created_at=venv_path.stat().st_ctime,
        )

        # Optional: link to a project
        if project_dir:
            self.link(project_dir, venv_path)

        self.venv = info
        return info

    # --- Activation (print-only) --------------------------------------------------
    def activation_command(self, venv: VenvInfo, shell: Optional[str] = None) -> str:
        """
        Return the shell command string to activate the venv. Does not execute it.
        shell: one of {'bash','zsh','fish','pwsh','cmd'} or None to auto-detect.
        """
        if self._is_windows():
            # Heuristic
            env = os.environ
            if not shell:
                if "PSModulePath" in env:
                    shell = "pwsh"
                elif env.get("ComSpec", "").lower().endswith("cmd.exe"):
                    shell = "cmd"
                else:
                    shell = "pwsh"
            if shell == "pwsh":
                return f'& "{(venv.path / "Scripts" / "Activate.ps1")}"'
            elif shell == "cmd":
                return f'"{(venv.path / "Scripts" / "activate.bat")}"'
            else:
                # allow bash via MSYS/git-bash etc.
                return f'source "{(venv.path / "Scripts" / "activate")}"'
        else:
            if not shell:
                shell = Path(os.environ.get("SHELL", "/bin/sh")).name
            if shell == "fish":
                return f'source "{(venv.path / "bin" / "activate.fish")}"'
            return f'source "{(venv.path / "bin" / "activate")}"'

    # --- Run commands inside a venv ----------------------------------------------
    def run_in(
        self,
        venv_path: Path,
        args: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        env: Optional[dict[str, str]] = None,
        check: bool = True,
        capture_output: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Execute a command using the venv's python interpreter: python -m <module> ... or arbitrary script.
        If args[0] == '-m', we run 'python -m ...'; otherwise we execute the given argv via the venv's python.
        """
        python = self._venv_python_path(venv_path)
        if not python.exists():
            raise FileNotFoundError(f"Python not found in venv: {python}")

        if args and args[0] == "-m":
            cmd = [str(python)] + list(args)
        elif args and args[0].endswith(".py"):
            cmd = [str(python)] + list(args)
        else:
            # Run arbitrary command via the venv's environment by prefixing python -c 'import runpy; ...'
            # But simpler & robust: use python -m to run modules like pip
            cmd = [str(python)] + list(args)

        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            check=check,
            capture_output=capture_output,
            text=True,
        )

    # --- Detection & listing ------------------------------------------------------
    def detect_venvs(self, root: Path, recursive: bool = True) -> Iterable[Path]:
        """
        Yield venv directories under root.
        """
        root = root.resolve()
        if not root.exists():
            return []

        ignore = {".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
        if not recursive:
            for p in root.iterdir():
                if p.name in ignore:
                    continue
                if self._looks_like_venv(p):
                    yield p
            return

        for p in root.rglob("*"):
            try:
                if p.is_dir():
                    name = p.name
                    if name in ignore:
                        continue
                    if self._looks_like_venv(p):
                        yield p
                        # Skip descending into this venv
                        # (pyvenv.cfg depth guard)
                        continue
            except PermissionError:
                continue

    def list_venvs(self) -> list[VenvInfo]:
        """
        List venvs in the global directory.
        """
        self.check_venv_dir()
        out: list[VenvInfo] = []
        for p in sorted(self.venv_dir.iterdir()):  # type: ignore[union-attr]
            if self._looks_like_venv(p):
                py = self._venv_python_path(p)
                out.append(
                    VenvInfo(
                        name=p.name,
                        path=p,
                        python=py,
                        platform="windows" if self._is_windows() else "posix",
                        created_at=p.stat().st_ctime,
                    )
                )
        return out

    # --- Exports (requirements + pipdeptree) -------------------------------------
    def export_lockfiles(self, venv_path: Path, out_dir: Path) -> tuple[Path, Path]:
        """
        Create requirements.txt and pipdeptree.txt for venv.
        If pipdeptree is not installed, install temporarily and remove afterwards.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        req = out_dir / "requirements.txt"
        pdt = out_dir / "pipdeptree.txt"

        # requirements
        self.run_in(venv_path, ["-m", "pip", "freeze"], capture_output=True)
        cp = self.run_in(venv_path, ["-m", "pip", "freeze"], capture_output=True)
        req.write_text(cp.stdout, encoding="utf-8")

        # pipdeptree
        has_pdt = self.run_in(
            venv_path,
            ["-m", "pip", "show", "pipdeptree"],
            check=False,
            capture_output=True,
        )
        injected = False
        if has_pdt.returncode != 0:
            self.run_in(
                venv_path, ["-m", "pip", "install", "pipdeptree>=2"], check=True
            )
            injected = True

        cp2 = self.run_in(
            venv_path, ["-m", "pipdeptree", "--freeze"], capture_output=True
        )
        pdt.write_text(cp2.stdout, encoding="utf-8")

        if injected:
            # Best-effort uninstall
            self.run_in(
                venv_path, ["-m", "pip", "uninstall", "-y", "pipdeptree"], check=False
            )

        return req, pdt

    # --- Transfer & delete --------------------------------------------------------
    def transfer(
        self, venv_path: Path, dest_root: Optional[Path] = None, move: bool = True
    ) -> Path:
        """
        Move or copy a venv to the global store (or a custom root).
        Returns the new path.
        """
        self.check_venv_dir()
        src = venv_path.resolve()
        if not self._looks_like_venv(src):
            raise ValueError(f"Not a valid venv: {src}")

        dest_root = (dest_root or self.venv_dir).resolve()  # type: ignore[union-attr]
        dest_root.mkdir(parents=True, exist_ok=True)

        base = src.name
        target = dest_root / base
        i = 1
        while target.exists():
            target = dest_root / f"{base}-{i}"
            i += 1

        if move:
            shutil.move(str(src), str(target))
        else:
            shutil.copytree(src, target, symlinks=True)

        return target.resolve()

    def _onerror_win_readonly(self, func, path, exc_info):
        # Helper for Windows read-only files
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    def delete(self, venv_path: Path, force: bool = False) -> None:
        """
        Delete a venv directory recursively.
        """
        vp = venv_path.resolve()
        if not self._looks_like_venv(vp):
            raise ValueError(f"Not a venv: {vp}")
        if not force:
            raise PermissionError("Refusing to delete venv without force=True")
        if self._is_windows():
            shutil.rmtree(vp, onerror=self._onerror_win_readonly)
        else:
            shutil.rmtree(vp)

    # --- Convenience: create+link current project --------------------------------
    def create_and_link_current(
        self,
        name: str,
        *,
        python: Optional[Path] = None,
        backend: str = "venv",
        with_pip: bool = True,
        project_dir: Optional[Path] = None,
    ) -> VenvInfo:
        """
        Create a global venv and link it to the given project (default: CWD).
        """
        project_dir = project_dir or Path.cwd()
        info = self.create(
            name=name,
            python=python,
            in_project=False,
            project_dir=project_dir,
            backend=backend,
            with_pip=with_pip,
        )
        return info

    # --- Simple JSON summary for CLI or logs -------------------------------------
    @staticmethod
    def summarize(info: VenvInfo) -> str:
        return json.dumps(
            {
                "name": info.name,
                "path": str(info.path),
                "python": str(info.python),
                "platform": info.platform,
                "created_at": info.created_at,
            },
            indent=2,
        )


# ------------------------ Example of minimal CLI hook ----------------------------
if __name__ == "__main__":
    import argparse

    m = ManagerVenv()
    parser = argparse.ArgumentParser(
        prog="ctfvenv-mini", description="Minimal venv manager demo"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="Create venv")
    p_create.add_argument("name")
    p_create.add_argument("--python", type=Path)
    p_create.add_argument("--backend", choices=["venv", "virtualenv"], default="venv")
    p_create.add_argument(
        "--link", action="store_true", help="Link to current directory after create"
    )

    p_which = sub.add_parser("which", help="Resolve venv for current project")

    p_activate = sub.add_parser("activate", help="Print activation command")
    p_activate.add_argument("--shell", choices=["bash", "zsh", "fish", "pwsh", "cmd"])

    p_list = sub.add_parser("list", help="List global venvs")

    p_export = sub.add_parser(
        "export", help="Export requirements and pipdeptree for resolved venv"
    )
    p_export.add_argument("--out", type=Path, default=Path.cwd())

    args = parser.parse_args()

    if args.cmd == "create":
        info = m.create(args.name, python=args.python, backend=args.backend)
        if args.link:
            m.link(Path.cwd(), info.path)
        print(ManagerVenv.summarize(info))

    elif args.cmd == "which":
        info = m.resolve_for(Path.cwd())
        if not info:
            print("No venv linked to this directory", file=sys.stderr)
            sys.exit(1)
        print(ManagerVenv.summarize(info))

    elif args.cmd == "activate":
        info = m.resolve_for(Path.cwd())
        if not info:
            print("No venv linked to this directory", file=sys.stderr)
            sys.exit(1)
        print(m.activation_command(info, shell=args.shell))

    elif args.cmd == "list":
        lst = m.list_venvs()
        for i in lst:
            print(ManagerVenv.summarize(i))

    elif args.cmd == "export":
        info = m.resolve_for(Path.cwd())

        if not info:
            print("No venv linked to this directory", file=sys.stderr)
            sys.exit(1)
        req, pdt = m.export_lockfiles(info.path, args.out)
        print(json.dumps({"requirements": str(req), "pipdeptree": str(pdt)}, indent=2))
