# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))

from __future__ import unicode_literals
import re

from recommonmark.parser import CommonMarkParser
from recommonmark.transform import AutoStructify
from docutils import nodes, transforms

# -- Project information -----------------------------------------------------

project = 'Turbinia'
copyright = '2020, Google Inc'
author = 'Turbinia maintainers'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc', 'sphinx.ext.doctest', 'sphinx.ext.coverage',
    'sphinx.ext.viewcode', 'sphinx.ext.napoleon', 'sphinx_markdown_tables',
    'recommonmark'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'design/*']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# The master toctree document.
master_doc = 'index'

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
html_sidebars = {
    '**': [
        'sidebar.html', 'localtoc.html', 'relations.html', 'sourcelink.html',
        'searchbox.html'
    ]
}

# Adding retries to linkchecks before declaring a link broken
linkcheck_retries = 3

# Output file base name for HTML help builder.
htmlhelp_basename = 'turbiniadoc'

html_logo = "images/turbinia-logo.jpg"


class ProcessLink(transforms.Transform):
  """Transform definition to parse .md references to internal pages."""

  default_priority = 1000

  def find_replace(self, node):
    """Parses URIs containing .md and replaces them with their HTML page."""
    if isinstance(node, nodes.reference) and 'refuri' in node:
      r = node['refuri']
      if r.endswith('.md'):
        r = r[:-3] + '.html'
        node['refuri'] = r

    return node

  def traverse(self, node):
    """Traverse the document tree rooted at node.
    node : docutil node
        current root node to traverse
    """
    self.find_replace(node)

    for c in node.children:
      self.traverse(c)

  # pylint: disable=arguments-differ,attribute-defined-outside-init
  # this was taken from GRR's config file for documentation
  def apply(self):
    self.current_level = 0
    self.traverse(self.document)


def setup(app):
  """Add custom parsers to Sphinx generation."""
  app.add_config_value(
      'recommonmark_config', {
          'enable_auto_doc_ref': False,
      }, True)
  app.add_transform(AutoStructify)
  app.add_transform(ProcessLink)
