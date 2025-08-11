# Architecture

## Explanation

ctfsolver is a framework that uses other libraries.

The ctfsolver class residing in the `src` folder, inherits managers.
It's manager has it's own functionality.

Other folders contain functionality that is displayed by :

- [the inline tool](./inline_tool/inline_tool_functionality.md)
- the package bash scripts

## Analytical structure of the package

```{include} ../../extra/architecture_tree.md

```

The following images have been created automatically with pylint.
To better understand them, just open them in a different tab and zoom in

The dots are inside `docs/sphinx/images`

```{graphviz} ../../images/classes_ctfsolver.dot

```

```{graphviz} ../../images/packages_ctfsolver.dot

```
