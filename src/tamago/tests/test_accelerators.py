"""Checks that the optional C accelerators are built where they should be.

Each accelerator has a pure-Python fallback, so a failed build doesn't break
anything; it only makes decoding far slower.  Builds that must have them (CI,
the Docker images, release wheels) set ``TAMAGO_REQUIRE_ACCEL=1``, which turns
a missing accelerator into a test failure here.
"""

import importlib
import os

import pytest

ACCELERATORS = [
    'tamago.formats.xp3._tlg_accel',
    'tamago.formats.yuris._murmur_accel',
]

REQUIRED = os.environ.get('TAMAGO_REQUIRE_ACCEL', '') not in ('', '0')


@pytest.mark.unit
@pytest.mark.skipif(not REQUIRED, reason="TAMAGO_REQUIRE_ACCEL not set")
@pytest.mark.parametrize('module', ACCELERATORS)
def test_accelerator_is_built(module):
    importlib.import_module(module)
