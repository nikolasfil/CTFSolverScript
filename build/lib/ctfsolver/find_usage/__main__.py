from ..src.ctfsolver import CTFSolver


if __name__ == "__main__":
    solver = CTFSolver()
    search_string = "from ctfsolver import CTFSolver"
    exclude_dirs = ["app_venv", ".git"]
    current_directory = "."

    solver.search_files(current_directory, exclude_dirs, search_string)
