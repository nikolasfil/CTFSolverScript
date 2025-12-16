from ctfsolver.config import CONFIG
from ctfsolver.managers.manager_folder import ManagerFolder
from pathlib import Path
import sys
import os
import subprocess
import inspect
import json


class ManagerVenv(ManagerFolder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **{**kwargs, "init_for_challenge": False})

        # Get the global venvs directory from config
        self.venv_dir = CONFIG["directories"].get("venvs", None)
        # Path to the venv to check
        self.venv_to_check = None
        # Get the current working directory
        self.get_current_dir()

        # Get where the command is run
        self.check_global_venv_dir()

    def check_global_venv_dir(self):
        if not self.venv_dir:
            raise ValueError("Virtual environment directory is not set.")

    def check_venv_dir(self, filepath):
        # Checks if the path parsed, is a virtual environment
        pyvenv = Path(filepath, "pyvenv.cfg")
        if pyvenv.exists():
            return True
        return False

    def activate(self, filepath):
        # Activates the venv parsed in the path
        if not self.check_venv_dir(filepath):
            raise ValueError("The path is not a valid virtual environment.")
        activate_script = (
            Path(filepath, "Scripts", "activate")
            if os.name == "nt"
            else Path(filepath, "bin", "activate")
        )
        if not activate_script.exists():
            raise FileNotFoundError(
                "Activate script not found in the virtual environment."
            )
        activate_command = (
            f"source {activate_script}" if os.name != "nt" else str(activate_script)
        )
        subprocess.call(activate_command, shell=True)

    def system_translator(self):
        # Will make it work between windows, linux and mac
        pass

    def get_python_executable(self):
        if not self.venv_to_check:
            raise ValueError("Virtual environment path is not set.")
        python_executable = (
            Path(self.venv, "Scripts", "python.exe")
            if os.name == "nt"
            else Path(self.venv_to_check, "bin", "python")
        )
        if not python_executable.exists():
            raise FileNotFoundError(
                "Python executable not found in the virtual environment."
            )
        self.python_executable = python_executable
        return python_executable

    def get_dependencies(self):
        # Get the list of dependencies for the virtual environment
        # Runs pip freeze inside the venv
        result = subprocess.run(
            [str(self.python_executable), "-m", "pip", "freeze"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"pip freeze failed: {result.stderr}")
        dependencies = result.stdout.strip().splitlines()
        return dependencies

    def install_pipdeptree(self):
        # Get the list of dependencies for the virtual environment
        result = subprocess.run(
            [str(self.python_executable), "-m", "install", "pipdeptree"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"pip freeze failed: {result.stderr}")
        dependencies = result.stdout.strip().splitlines()
        return dependencies

    def get_pipdeptree(self):
        # Get the list of dependencies for the virtual environment
        # Get the python executable
        result = subprocess.run(
            # [str(self.python_executable), "-m", "pipdeptree", "-j"],
            [str(self.python_executable), "-m", "pipdeptree", "--json-tree"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"pip freeze failed: {result.stderr}")
        dependencies = json.loads(result.stdout)
        return dependencies

    def look_for_venvs(self, filepath: str = None):
        """
        Recursively searches for Python virtual environments within a specified directory.
        Args:
            filepath (str, optional): The path to the directory in which to search for virtual environments.
                If not provided, the search will be performed in the instance's `venv_dir` attribute.
        Returns:
            list[Path]: A list of Path objects representing directories identified as Python virtual environments.
        Raises:
            FileNotFoundError: If the specified path does not exist or is not a directory.
        Notes:
            - A directory is considered a virtual environment if `self.check_venv_dir(item)` returns True.
            - The search is performed recursively using `Path.rglob("*")`.
        """

        # Looks for virtual environments recursively in the global venvs directory
        venvs_found = []
        search_path = Path(self.venv_dir) if not filepath else Path(filepath)
        if not search_path.exists() or not search_path.is_dir():
            raise FileNotFoundError(
                "The specified path does not exist or is not a directory."
            )
        for item in search_path.rglob("*"):
            if item.is_dir() and self.check_venv_dir(item):
                venvs_found.append(item)
        return venvs_found

    def save_dependencies(self):
        # Saves the list of dependencies for the virtual environment
        pass

    def clean_venv(self):
        # Cleans the virtual environment
        pass

    def move_venv(self, folder: Path = None):
        # Moves the virtual environment to the global location
        self.get_current_dir()
        self.look_for_venvs()
        self.venv_to_check = Path(self.parent)
        self.get_python_executable()
        self.activate(self.venv_to_check)

        dep = self.get_pipdeptree()

        # write to the challnenge information
        # retrieve the venv destination and update
        # create the venv folder if it does not exist
        # install the pipdeptree info
        # remove the local venv

    def create_shortcut(self):
        # Creates a shortcut for the virtual environment
        pass

    def delete_venv(self, folder: Path):
        """
        Deletes the virtual environment directory.

        Args:
            folder (Path): The path to the virtual environment folder to delete.
        """
        if folder.exists() and folder.is_dir():
            self.delete_folder(folder)
        else:
            raise FileNotFoundError("The specified virtual environment does not exist.")

    def testing(self):
        self.get_current_dir()

        self.venv_to_check = Path(self.parent, "venvs", "venv_app")
        # self.venv_to_check = Path(self.parent)
        self.get_python_executable()
        self.activate(self.venv_to_check)
        # dep = self.get_dependencies()
        dep = self.get_pipdeptree()
        for i, item in enumerate(dep):
            print(i, item["package_name"])


if __name__ == "__main__":
    manager = ManagerVenv()
