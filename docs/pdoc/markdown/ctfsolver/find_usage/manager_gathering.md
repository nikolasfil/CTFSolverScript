Module ctfsolver.find_usage.manager_gathering
=============================================

Classes
-------

`ManagerGathering(*args, **kwargs)`
:   ManagerFunction provides utility methods for introspecting and managing functions within a class and Python source files.
    
    This class includes methods to:
        - List all callable functions defined in the class.
        - Retrieve references to function usages in a given file.
        - Extract function definitions from Python files using the AST module.
    
    Methods:
        get_self_functions():
            Lists all callable functions of the class instance, excluding special methods.
    
        get_function_reference(function, file):
            Finds and returns all lines in the specified file where the given function name appears.
    
            Args:
                function (str): The name of the function to search for.
                file (str): The path to the file to search in.
    
            Returns:
                list[str]: Lines from the file containing the function name.
    
            Raises:
                ValueError: If the function is not found in the class.
    
        get_functions_from_file(file_path, function_name=None):
            Parses the given Python file and returns function definitions using AST.
    
            Args:
                file_path (Path): Path to the Python file.
                function_name (str, optional): Specific function name to search for.
    
            Returns:
                list[ast.FunctionDef] | ast.FunctionDef | None: List of function definitions, a single function definition, or None.
    
        find_function_from_file(file_path, function_name):
            Deprecated. Use get_functions_from_file instead.
    
    Initialize the class

    ### Ancestors (in MRO)

    * ctfsolver.managers.manager_functions.ManagerFunction
    * ctfsolver.managers.manager_folder.ManagerFolder

    ### Methods

    `adding_to_file(self, filename: str, method_source: str)`
    :

    `check_functions(self, target_info, solution_info, solution_name)`
    :

    `gathering_all_solution_files(self)`
    :

    `get_gathering_target(self)`
    :

    `get_org_information(self)`
    :

    `handling_global_config(self)`
    :

    `main(self)`
    :

    `method_enumeration(self, target_methods, method_name)`
    :   Enumerates methods in target_methods that match method_name
        with optional numbering (e.g., foo, foo_1, foo_2).

    `renaming_method(self)`
    :

    `tabbing(self, text: str, num: int = 1, function=False, space=True, space_num=4)`
    :