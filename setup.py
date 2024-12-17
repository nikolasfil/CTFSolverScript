import setuptools
import os

with open("app/README.md", "r") as fh:
    long_description = fh.read()

version = "0.0.1"
with open("VERSION", "r") as fv:
    version = fv.read()


requirements = []
with open("requirements.txt", "r") as fr:
    requirements = fr.read().splitlines()

setuptools.setup(
    name="ctfsolver",
    version=version,
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
    install_requires=requirements,
    # namespace_packages=["ctfsolver"],
    # package_data={"ctfsolver": ["files/*"]},
    extras_require={
        "dev": ["pytest>=6.2.4", "twine>=3.4.2"],
        "docs": ["pdoc3>=0.9.2"],
    },
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            # "folders=ctfsolver.folders.__main__:main",
            "folders=ctfsolver.scripts.run_folders:main",
            "run=ctfsolver.scripts.run_solution:main",
            "templ=ctfsolver.scripts.__main__:run_template",
            "find_usage=ctfsolver.scripts.run_find_usage:main",
        ]
    },
)
