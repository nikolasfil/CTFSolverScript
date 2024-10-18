import setuptools
import os

with open("app/README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ctfsolver",
    version="0.0.3",
    description="An all in one library for solving CTF challenges",
    package_dir={"": "app"},
    packages=setuptools.find_packages(where="app"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nikolasfil/CTFSolverScript",
    author="Nikolas Filippatos",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "bcrypt>=4.2.0",
        "capstone>=5.0.3",
        "certifi>=2024.8.30",
        "cffi>=1.17.1",
        "charset-normalizer>=3.3.2",
        "colored-traceback>=0.4.2",
        "cryptography>=43.0.1",
        "idna>=3.10",
        "intervaltree>=3.1.0",
        "Mako>=1.3.5",
        "MarkupSafe>=2.1.5",
        "packaging>=24.1",
        "paramiko>=3.5.0",
        "plumbum>=1.8.3",
        "psutil>=6.0.0",
        "pwntools>=4.13.0",
        "pycparser>=2.22",
        "pyelftools>=0.31",
        "Pygments>=2.18.0",
        "PyNaCl>=1.5.0",
        "pyserial>=3.5",
        "PySocks>=1.7.1",
        "python-dateutil>=2.9.0.post0",
        "requests>=2.32.3",
        "ROPGadget>=7.4",
        "rpyc>=6.0.0",
        "six>=1.16.0",
        "sortedcontainers>=2.4.0",
        "unicorn>=2.1.0",
        "unix-ar>=0.2.1",
        "urllib3>=2.2.3",
        "zstandard>=0.23.0",
    ],
    # namespace_packages=["ctfsolver"],
    # package_data={"ctfsolver": ["files/*"]},
    extras_require={
        "dev": ["pytest>=6.2.4", "twine>=3.4.2"],
    },
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            # "folders=ctfsolver.folders.__main__:main",
            "folders=ctfsolver.scripts.run_folders:main",
            "run=ctfsolver.scripts.run_solution:main",
        ]
    },
)
