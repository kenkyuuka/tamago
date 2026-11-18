"""Python types for the PSB values that have no exact Python equivalent.

A PSB value tree decodes to ``None``, ``bool``, ``int``, ``float``, ``str``,
``list`` and ``dict``, plus the types here:

- :class:`Resource` and :class:`ExtraResource` reference the file's resource
  chunks by index (textures, sounds, embedded files).
- :class:`Float32` marks a float stored in single precision, so that writing a
  tree back stores it the same way.  Plain ``float`` values are stored as
  doubles.
- :class:`IntArray` is the packed integer array, which is a value type of its
  own, distinct from a list of integers.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Resource:
    """A reference to resource chunk *index* (``PSB.resources[index]``)."""

    index: int


@dataclass(frozen=True)
class ExtraResource:
    """A reference to extra resource chunk *index* (``PSB.extra_resources[index]``, version 4 and later)."""

    index: int


class Float32(float):
    """A float stored in single precision.

    Its value is the exact single-precision value, widened to a double.
    """

    __slots__ = ()

    def __repr__(self):
        return f'Float32({float(self)!r})'


class IntArray(list):
    """A packed array of integers, stored as one value rather than as a list."""

    __slots__ = ()

    def __repr__(self):
        return f'IntArray({list(self)!r})'
