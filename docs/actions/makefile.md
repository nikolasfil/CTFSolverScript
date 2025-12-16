Makefile for managing Python package setup and documentation.

Targets:
create-venv Create a virtual environment.
clean-venv Remove the virtual environment.
venv-upgrade-pip Upgrade pip in the virtual environment.
setup-old Build source distribution and wheel using setup.py.
setup-toml Build source distribution and wheel using pyproject.toml.
install-pack-dev Install the package in editable mode.
install-req-dev Install development dependencies.
install-req-docs Install documentation dependencies.
setup-all-dev Create venv, upgrade pip, and install all dependencies.
upload-pypi Upload the package to PyPI using twine.
doc-pdoc Generate documentation using pdoc.
doc-pdoc-host Host documentation using pdoc.
