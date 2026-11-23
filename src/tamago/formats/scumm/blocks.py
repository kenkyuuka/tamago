"""The SCUMM block (chunk) container: 4-byte tag, big-endian size including the header, body.

Shared by the LucasArts (v5+) and Humongous resource files. Some files are
obfuscated by XORing every byte with :data:`XOR_KEY`.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass

HEADER_SIZE = 8
XOR_KEY = 0x69

# Tags are upper-case letters and digits, possibly space-padded ("SOU ").
_TAG_RE = re.compile(rb'[A-Z][A-Z0-9 ]{3}')
_HEADER = struct.Struct('>4sI')


class BlockError(ValueError):
    """A block header is malformed or runs past its container."""


def is_tag(raw: bytes) -> bool:
    """Whether *raw* (4 bytes) looks like a block tag."""
    return len(raw) == 4 and _TAG_RE.fullmatch(raw) is not None


def deobfuscate(data: bytes, key: int = XOR_KEY) -> bytes:
    """XOR every byte of *data* with *key* (its own inverse)."""
    if not key:
        return bytes(data)
    return bytes(data).translate(bytes(b ^ key for b in range(256)))


def detect_key(header: bytes) -> int | None:
    """The XOR key (0 or :data:`XOR_KEY`) under which *header* starts with a block tag, or ``None``."""
    head = bytes(header[:4])
    if is_tag(head):
        return 0
    if is_tag(deobfuscate(head)):
        return XOR_KEY
    return None


@dataclass(frozen=True)
class Block:
    """One block inside a buffer: ``data[offset:offset + size]`` is the whole block, header included."""

    tag: str
    offset: int
    size: int
    data: bytes

    @property
    def body_offset(self) -> int:
        return self.offset + HEADER_SIZE

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def body(self) -> bytes:
        return self.data[self.body_offset : self.end]

    @property
    def raw(self) -> bytes:
        """The whole block, header included."""
        return self.data[self.offset : self.end]

    def children(self) -> list[Block]:
        """The blocks in this block's body; raises :class:`BlockError` if it is not a container."""
        return list(iter_blocks(self.data, self.body_offset, self.end))

    def try_children(self) -> list[Block] | None:
        """The blocks in this block's body, or ``None`` if the body is not a sequence of blocks."""
        try:
            blocks = self.children()
        except BlockError:
            return None
        return blocks or None

    def find(self, tag: str) -> Block | None:
        """The first child with *tag*, or ``None``."""
        for child in self.try_children() or ():
            if child.tag == tag:
                return child
        return None

    def find_all(self, tag: str) -> list[Block]:
        return [child for child in self.try_children() or () if child.tag == tag]


def read_header(data: bytes, offset: int) -> tuple[str, int]:
    """The tag and size of the block at *offset*."""
    if offset + HEADER_SIZE > len(data):
        raise BlockError(f"truncated block header at {offset:#x}")
    raw_tag, size = _HEADER.unpack_from(data, offset)
    if not is_tag(raw_tag):
        raise BlockError(f"bad block tag {raw_tag!r} at {offset:#x}")
    return raw_tag.decode('ascii'), size


def iter_blocks(data: bytes, start: int = 0, end: int | None = None) -> Iterator[Block]:
    """The blocks packed back to back in ``data[start:end]``.

    A tail shorter than a block header is ignored: some containers in the
    games end with a stray byte after their last block.
    """
    if end is None:
        end = len(data)
    offset = start
    while end - offset >= HEADER_SIZE:
        tag, size = read_header(data, offset)
        if size < HEADER_SIZE or offset + size > end:
            raise BlockError(f"block {tag} at {offset:#x} has bad size {size}")
        yield Block(tag, offset, size, data)
        offset += size


def top_level(data: bytes) -> list[Block]:
    """The blocks at the top level of a whole file."""
    return list(iter_blocks(data))
