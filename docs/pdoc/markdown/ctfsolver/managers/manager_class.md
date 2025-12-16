Module ctfsolver.managers.manager_class
=======================================
manager_class.py

Provides the ManagerClass for inspecting Python classes in source files, including their methods,
class attributes, and instance attributes, with optional support for inherited members from base classes
located in nearby files or directories.

This module is useful for static analysis, code introspection, and documentation generation tasks
where understanding the structure and inheritance of Python classes is required.

Classes:
    ManagerClass: Inspects Python class definitions and their members, supporting inheritance resolution
                  across multiple files and directories.

Example:
    inspector = ManagerClass(search_paths=["src", "package"])

Attributes:
    None

About self.inspect return :

from typing import TypedDict, Dict, List, Optional
from typing import Literal  # if on 3.8, use: from typing_extensions import Literal

class MethodInfo(TypedDict):
    kind: Literal["instance", "class", "static", "property", "property-setter", "property-deleter"]
    async: bool
    decorators: List[Optional[str]]   # result of unparse; may be None
    args: List[str]                   # parameter names as written
    returns: Optional[str]            # return annotation (unparsed) or None
    source: Optional[str]             # exact segment if available, else unparsed; may be None
    defined_in: str                   # class name where defined
    file: str                         # file path where defined (string path)
    inherited: bool                   # True if came from a base class

class ClassAttrInfo(TypedDict):
    source: Optional[str]             # assignment statement source
    value_source: Optional[str]       # RHS expression source (if present)
    defined_in: str
    file: str
    inherited: bool

class InstanceAttrOccurrence(TypedDict):
    method: str                       # method where self.<attr> was assigned
    lineno: Optional[int]             # line number (if available)
    source: Optional[str]             # assignment statement source
    defined_in: str
    file: str
    inherited: bool

class OriginInfo(TypedDict):
    class_: str                       # class name of origin (key name 'class' in dict; see below)
    file: str
    inherited: bool

# Because 'class' is a reserved word in Python, we store it in the dict as 'class'
# but expose a typing alias that maps to 'class' at runtime. Type checkers accept this pattern:
OriginMap = Dict[str, OriginInfo]     # maps symbol name -> origin info

class Origins(TypedDict):
    methods: OriginMap
    class_attributes: OriginMap
    instance_attributes: OriginMap

class ClassRefInfo(TypedDict):
    file: str
    source: Optional[str]             # class block source
    bases: List[Optional[str]]        # base expressions (unparsed); may be None
    decorators: List[Optional[str]]   # class decorators (unparsed); may be None

class ClassInspectionResult(TypedDict):
    name: str
    mro: List[str]                                      # best-effort: derived first, then bases
    methods: Dict[str, MethodInfo]                      # method name -> details
    class_attributes: Dict[str, ClassAttrInfo]          # class attr name -> details
    instance_attributes: Dict[str, List[InstanceAttrOccurrence]]  # self.<attr> -> occurrences
    origins: Origins
    classes: Dict[str, ClassRefInfo]                    # per-class summary (derived and bases)

Classes
-------

`ManagerClass(search_paths: List[str | pathlib._local.Path] | None = None)`
:   Inspect Python classes in source files, including inherited members found in nearby files.
    
    Usage:
        inspector = ClassInspector(search_paths=["src", "package"])
        details = inspector.inspect("path/to/file.py", "MyClass", include_inherited=True)

    ### Methods

    `example_printing(self, file_path: str, classname: str)`
    :

    `get_classes_in_file(self, file_path: str | pathlib._local.Path) ‑> list[str]`
    :   Opens a Python file and returns a list of class names defined in that file.
        
        Args:
            file_path (str | Path): Path to the Python source file.
        
        Returns:
            list[str]: List of class names found in the file.

    `inspect(self, file_path: str | pathlib._local.Path, class_name: str, include_inherited: bool = True, extra_search_paths: List[str | pathlib._local.Path] | None = None) ‑> Dict[str, Any]`
    :   Parse a Python file, locate `class_name`, and return its functions/attributes.
        If `include_inherited` is True, also pulls in members from base classes found
        within search paths (default: the file's directory + self.default_search_paths + extra_search_paths).
        
        Returns:
          {
            "name": str,
            "mro": [derived, base1, base2, ...],      # best-effort order
            "methods": { name: {..., defined_in, file, inherited } },
            "class_attributes": { name: {..., defined_in, file, inherited } },
            "instance_attributes": { name: [ {..., defined_in, file, inherited }, ...] },
            "origins": {...},                          # where each symbol came from
            "classes": { class_name: {"file": str, "source": str, "bases": [...], "decorators":[...]} }
          }