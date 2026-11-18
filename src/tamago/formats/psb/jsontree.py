"""Converting PSB value trees to and from JSON-compatible values.

JSON has no types for some PSB values, so they become tagged objects, each
with a single ``$`` key:

==================== ======================================================
``{"$resource": n}`` :class:`.Resource` *n*
``{"$extra": n}``    :class:`.ExtraResource` *n*
``{"$double": x}``   a float stored in double precision
``{"$intarray": []}`` an :class:`.IntArray`
``{"$dict": {...}}`` a real dictionary that would otherwise look like a tag
==================== ======================================================

Plain JSON numbers with a fraction or exponent are single-precision floats
(:class:`.Float32`), written with the fewest digits that read back as the
same single-precision value (``0.6``, not ``0.6000000238418579``).
"""

from __future__ import annotations

import math
import struct

from tamago.formats.psb.values import ExtraResource, Float32, IntArray, Resource

_TAGS = ('$resource', '$extra', '$double', '$intarray', '$dict')


def _to_f32(x: float) -> float:
    return struct.unpack('<f', struct.pack('<f', x))[0]


def _short_f32(v: float) -> float:
    """The double with the shortest repr that rounds to the single-precision *v*."""
    if not math.isfinite(v) or v == 0.0:
        return float(v)
    for digits in range(1, 10):
        x = float(f'{v:.{digits}g}')
        if _to_f32(x) == v:
            return x
    return float(v)


def to_json(v):
    """Return a JSON-compatible copy of the value tree *v*."""
    if isinstance(v, dict):
        out = {k: to_json(x) for k, x in v.items()}
        if len(out) == 1 and next(iter(out)) in _TAGS:
            return {'$dict': out}
        return out
    if isinstance(v, IntArray):
        return {'$intarray': list(v)}
    if isinstance(v, list):
        return [to_json(x) for x in v]
    if isinstance(v, Float32):
        return _short_f32(float(v))
    if isinstance(v, float):
        return {'$double': v}
    if isinstance(v, Resource):
        return {'$resource': v.index}
    if isinstance(v, ExtraResource):
        return {'$extra': v.index}
    return v


def from_json(v):
    """Rebuild a value tree from :func:`to_json`'s output."""
    if isinstance(v, dict):
        if len(v) == 1:
            ((k, x),) = v.items()
            if k == '$resource':
                return Resource(int(x))
            if k == '$extra':
                return ExtraResource(int(x))
            if k == '$double':
                return float(x)
            if k == '$intarray':
                return IntArray(int(i) for i in x)
            if k == '$dict':
                return {kk: from_json(xx) for kk, xx in x.items()}
        return {k: from_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [from_json(x) for x in v]
    if isinstance(v, float):
        return Float32(_to_f32(v))
    return v
