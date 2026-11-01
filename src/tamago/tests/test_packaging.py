from importlib.resources import files

import pytest


@pytest.mark.unit
def test_py_typed_marker_present():
    """PEP 561: the marker tells type checkers to use tamago's inline annotations."""
    assert files('tamago').joinpath('py.typed').is_file()
