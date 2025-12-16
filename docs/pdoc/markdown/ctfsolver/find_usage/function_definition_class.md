Module ctfsolver.find_usage.function_definition_class
=====================================================
function_definition_class.py

Provides a class for traversing Python Abstract Syntax Trees (AST) to locate specific function definitions.

This module defines the FunctionDefFinder class, which extends ast.NodeVisitor to search for a function definition node by name within a Python AST. It is useful for static code analysis, refactoring tools, or any application that requires inspection of Python source code structure.

Classes:
    FunctionDefFinder: AST NodeVisitor to find a specific function definition by name.

Example:
    finder = FunctionDefFinder(function_target="my_function")
    finder.visit(ast.parse(source_code))
    found_node = finder.function_def

Classes
-------

`FunctionDefFinder(*args, **kwargs)`
:   AST NodeVisitor to find a specific function definition in a Python AST.
    
    Attributes:
        function_def (Optional[ast.FunctionDef]): The found function definition node.
        function_target (Optional[str]): The name of the function to search for.
        visit_list (List[ast.FunctionDef]): List of visited function definition nodes.
    
    Functions:
        visit_FunctionDef: Visits a function definition node in the AST.
    
    Initializes the FunctionDefFinder.
    
    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments. Can include 'function_target' (str).

    ### Ancestors (in MRO)

    * ast.NodeVisitor

    ### Methods

    `visit_FunctionDef(self, node: ast.FunctionDef) ‑> None`
    :   Visits a function definition node in the AST.
        
        Args:
            node (ast.FunctionDef): The function definition node to visit.