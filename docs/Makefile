SHELL := /bin/bash 
DEST=.
PYTHON=python3
PACKAGE?=ctfsolver
PACKAGE_DIR=../app/ctfsolver

SPHINX_DIR = sphinx


create-graphviz :

	pyreverse -o dot -p $(PACKAGE) $(PACKAGE_DIR)
	mv classes_$(PACKAGE).dot $(SPHINX_DIR)/images/
	mv packages_$(PACKAGE).dot $(SPHINX_DIR)/images/
	dot -Tpng $(SPHINX_DIR)/images/classes_$(PACKAGE).dot -o $(SPHINX_DIR)/images/classes_$(PACKAGE).png
	dot -Tpng $(SPHINX_DIR)/images/packages_$(PACKAGE).dot -o $(SPHINX_DIR)/images/packages_$(PACKAGE).png
