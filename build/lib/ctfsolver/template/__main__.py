from ctfsolver import CTFSolver
from pathlib import Path


class Templater(CTFSolver):
    def main(self):

        file_called_path = Path(self.file_called_frame[2].filename)
        parent = Path(file_called_path).parent

        file = Path(parent, "solution_template.py")
        with open(file, "r") as f:
            template = f.read()

        with open(Path(self.folder_payloads, "solution.py"), "w") as f:
            f.write(template)


if __name__ == "__main__":
    templater = Templater()
    templater.main()
