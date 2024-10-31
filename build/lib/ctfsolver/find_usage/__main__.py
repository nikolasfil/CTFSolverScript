import os


def search_files(directory, exclude_dirs, search_string):
    for root, dirs, files in os.walk(directory):
        # Exclude specified directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r") as f:
                    # Check if the search string is in the file
                    if search_string in f.read():
                        print(file_path)
            except (IOError, UnicodeDecodeError):
                # Handle files that cannot be opened or read
                continue


if __name__ == "__main__":
    search_string = "from ctfsolver import CTFSolver"
    exclude_dirs = ["app_venv", ".git"]
    current_directory = "."

    search_files(current_directory, exclude_dirs, search_string)
