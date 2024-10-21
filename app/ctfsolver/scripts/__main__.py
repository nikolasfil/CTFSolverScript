from run_folders import main as folders
from run_solution import main as run
import subprocess
import sys


def running(module):
    result = subprocess.run([sys.executable, "-m", module], check=True)
    sys.exit(result.returncode)


def run_template():
    # folders()
    running("ctfsolver.template")
