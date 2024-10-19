import subprocess
import sys
from pathlib import Path
from ..src.ctfsolver import CTFSolver


def main():
    s = CTFSolver()

    solution_path = Path(s.folder_payloads, "solution.py")

    if not solution_path.exists():
        print(f"File {solution_path} does not exist")
        sys.exit(1)

    result = subprocess.run(
        [sys.executable, str(solution_path)], cwd=s.parent, check=True
    )
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()