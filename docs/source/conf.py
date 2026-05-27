"""Sphinx configuration for AgentForensics documentation."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))

from agentforensics import __version__  # noqa: E402

project = "AgentForensics"
copyright = "2026, Carlos Rocha"
author = "Carlos Rocha"
release = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
]

templates_path = ["_templates"]
exclude_patterns: list[str] = []

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_theme = "furo"
html_static_path: list[str] = []
