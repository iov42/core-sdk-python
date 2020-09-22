"""Sphinx configuration."""
from datetime import datetime


project = "Python library for convenient access to the iov42 platform."
author = "Max Hofer"
copyright = f"{datetime.now().year}, {author}"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon"]
autodoc_typehints = "description"
