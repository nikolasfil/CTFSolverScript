# Installation

There are many ways to install the package

## PYPI install

```{code-block} python
:linenos:
pip install ctfsolver
```

## Github package install

```{code-block} bash
pip install ctfsolver @ git+ssh://git@github.com/nikolasfil/CTFSolverScript.git
```

## Github repo clone and install

```{code-block} bash
:linenos:
git clone https://github.com/yourusername/ctfsolver.git
cd ctfsolver
```

## Makefile Installation Commands

You can use the provided Makefile for various installation options:

### Development install

```bash
make install-dev
```

### Editable install (for development)

```bash
make install-pack-dev
```

### Install development dependencies

```bash
make install-req-dev
```

### Install documentation dependencies

```bash
make install-req-docs
```

### Install all dependencies (dev + docs)

```bash
make install-req-all
```

### All-in-one setup for development

```bash
make setup-all-dev
```

### All-in-one setup for usage

```bash
make setup
```
