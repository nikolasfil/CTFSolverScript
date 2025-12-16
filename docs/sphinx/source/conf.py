from __future__ import annotations
import os
import sys
from datetime import datetime
from pathlib import Path

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

root_path = Path(__file__).parent.parent.parent.parent


sys.path.insert(0, str(root_path))

project = "ctfsolver"
author = "Nikolas Filippatos"
copyright = f"{datetime.now():%Y}, {author}"
release = open(Path(root_path, "VERSION")).read().strip()

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",  # Google/NumPy docstrings
    # "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.todo",
    "sphinx.ext.doctest",
    "myst_parser",  # Markdown support
    "sphinx_copybutton",
    "sphinx_autodoc_typehints",  # nice type hints rendering
    "autoapi.extension",
    "sphinx.ext.linkcode"
]

exclude_patterns = []

autosectionlabel_prefix_document = True

# Autosummary
autosummary_generate = True



# Autodoc defaults
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "inherited-members": True,
    "show-inheritance": True,
}
autoclass_content = "class"  # or "both"
add_module_names = False  # cleaner headings


# Napoleon (if using Google/NumPy)
napoleon_google_docstring = True
napoleon_numpy_docstring = False  # set True if you use NumPy style
napoleon_include_init_with_doc = False
napoleon_use_param = True
napoleon_use_rtype = True

# MyST (Markdown) settings
myst_enable_extensions = ["colon_fence", "deflist", "substitution", "fieldlist"]

# Intersphinx (cross-link to Python stdlib, etc.)
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "scapy": ("https://scapy.readthedocs.io/en/latest/", None),
}




autodoc_typehints = "description"
autodoc_typehints_format = "short"


# --------------- Autoapi ----

def linkcode_resolve(domain, info):
    if domain != "py":
        return None
    if not info["module"]:
        return None

    filename = info["module"].replace(".", "/")
    return f"https://github.com/nikolasfil/CTFSolver/blob/main/{filename}.py"


project_path = Path(root_path, "app", "ctfsolver")

autoapi_dirs = [str(project_path)]
autoapi_add_toctree_entry = True  # puts "API Reference" in nav
autoapi_root = "api"  # generated pages under api/
autoapi_generate_api_docs = True
autoapi_keep_files = False  # clean regenerated files
autoapi_member_order = "bysource"  # keep your code order
autoapi_python_class_content = "class"  # or "both"
autoapi_python_use_implicit_namespaces = True

autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
]

# Optional: don’t scan compiled caches and tests
autoapi_ignore = [
    "**/__pycache__/**",
    "**/test/**",
    "*manager_files_re.None",
]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# Theme
# html_theme = "sphinx_rtd_theme"
html_theme = "furo"
html_theme_options = {
    "light_css_variables": {},
    "dark_css_variables": {},
}
html_static_path = ["_static"] if (Path(__file__).parent / "_static").exists() else []
templates_path = (
    ["_templates"] if (Path(__file__).parent / "_templates").exists() else []
)


todo_include_todos = True
nitpicky = True  # warn on broken cross-refs
