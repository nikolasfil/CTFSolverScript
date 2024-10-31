from ..src.ctfsolver import CTFSolver


if __name__ == "__main__":
    solver = CTFSolver()
    search_string = "from ctfsolver import CTFSolver"
    exclude_dirs = ["app_venv", ".git"]
    current_directory = "."

    try:

        solver.search_files(
            directory=current_directory,
            exclude_dirs=exclude_dirs,
            search_string=search_string,
            display=True,
        )
    except KeyboardInterrupt as k:
        print("Stopping the search")
    except Exception as e:
        print(e)
