import ast
import re
import sys
from importlib.metadata import packages_distributions, requires
from importlib.resources import files

import pytest


def _normalize(name):
    """PEP 503 normalization, so ``Pillow`` and ``pillow`` compare equal."""
    return re.sub(r'[-_.]+', '-', name).lower()


# Standard-library modules added after the oldest Python tamago supports, which
# it imports behind a version check (``sys.stdlib_module_names`` on that
# oldest version doesn't list them).
_NEWER_STDLIB = frozenset({'tomllib'})  # Python 3.11


def _iter_sources(root):
    for entry in root.iterdir():
        if entry.is_dir():
            if entry.name not in ('tests', '__pycache__'):
                yield from _iter_sources(entry)
        elif entry.name.endswith('.py'):
            yield entry


def _third_party_imports():
    """Top-level modules imported by tamago's own code that aren't in the standard library."""
    found = set()
    for source in _iter_sources(files('tamago')):
        for node in ast.walk(ast.parse(source.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split('.')[0]
                if top != 'tamago' and top not in sys.stdlib_module_names and top not in _NEWER_STDLIB:
                    found.add(top)
    return found


@pytest.mark.unit
def test_py_typed_marker_present():
    """PEP 561: the marker tells type checkers to use tamago's inline annotations."""
    assert files('tamago').joinpath('py.typed').is_file()


@pytest.mark.unit
def test_third_party_imports_are_declared_dependencies():
    """A module imported by tamago but missing from its dependencies breaks a clean install.

    Test environments pull in many packages transitively (pytest brings ``tomli`` on 3.10),
    so an undeclared import can pass every test yet fail for users.
    """
    declared = {
        _normalize(re.match(r'[A-Za-z0-9._-]+', req).group())
        for req in requires('tamagoarc') or []
        if 'extra ==' not in req  # optional extras aren't installed by default
    }
    dists_by_module = packages_distributions()

    undeclared = {}
    for module in _third_party_imports():
        # A module that isn't installed here is assumed to share its distribution's name.
        dists = {_normalize(d) for d in dists_by_module.get(module, [module])}
        if not dists & declared:
            undeclared[module] = sorted(dists)

    assert not undeclared, f'imported but not declared in [project] dependencies: {undeclared}'
