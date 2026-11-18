import argparse
import os
import pathlib
import sys

from tamago.formats.blackrainbow.bmd import bmd_to_png, is_bmd, png_to_bmd
from tamago.formats.blackrainbow.datfile import KINDS, DATFile

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
_KIND_NAMES = {name: kind for kind, name in KINDS.items()}


def _game_id(text):
    try:
        value = int(text, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a hexadecimal value: {text!r}") from None
    if not 0 <= value <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError(f"must fit in 32 bits: {text!r}")
    return value


def _slots(text):
    try:
        value = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1: {text!r}")
    return value


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _swap_suffix(path: pathlib.Path, old: str, new: str) -> pathlib.Path:
    if path.suffix.lower() == old:
        return path.with_suffix(new)
    return path


def _convert_tree(source: pathlib.Path, dest: pathlib.Path, select, transform, rename, what: str):
    """Convert *source* (a file or directory tree) into *dest*.

    A single file must be one *select* accepts and is written to *dest* as
    given.  In a directory, converted files are renamed with *rename* and other
    files are copied unchanged.
    """
    if not source.is_dir():
        data = source.read_bytes()
        if not select(data):
            _fail(f"{source} is not a {what}")
        try:
            data = transform(data)
        except ValueError as e:
            _fail(f"{source}: {e}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, 'xb') as f:
            f.write(data)
        return
    for root, dirs, files in os.walk(source):
        dirs.sort()
        for name in sorted(files):
            path = pathlib.Path(root, name)
            target = dest / path.relative_to(source)
            data = path.read_bytes()
            if select(data):
                try:
                    data = transform(data)
                except ValueError as e:
                    _fail(f"{path}: {e}")
                target = rename(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, 'xb') as f:
                f.write(data)


class BlackRainbowHandler:
    """Format handler for BlackRainbow's ADVDX engine: resource archives and _BMD images."""

    def add_extract_args(self, parser):
        parser.add_argument(
            '--convert-bmd',
            action='store_true',
            help='write _BMD images as PNG files (create converts them back)',
        )

    def add_create_args(self, parser):
        parser.add_argument(
            '--kind',
            choices=sorted(_KIND_NAMES),
            help='what the archive holds (default: from the manifest, or guessed from the files)',
        )
        parser.add_argument(
            '--game-id',
            type=_game_id,
            help='hex game ID for script and read archives, which the game checks (default: from the manifest, or 0)',
        )
        parser.add_argument(
            '--slots',
            type=_slots,
            help='size of the slot table (default: from the manifest, or one past the highest slot used)',
        )

    def add_commands(self, subparsers):
        """Add ``decode-bmd`` and ``encode-bmd`` for converting _BMD images."""
        to_png = subparsers.add_parser(
            'decode-bmd',
            help='Convert _BMD images to PNG',
            description='Convert a _BMD image, or every _BMD under a directory, to PNG '
            '(.bmd becomes .png; other files are copied unchanged).',
        )
        to_png.add_argument('input', type=pathlib.Path, help='_BMD file or directory')
        to_png.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_png.set_defaults(func=self.cmd_decode_bmd)

        to_bmd = subparsers.add_parser(
            'encode-bmd',
            help='Convert PNG images to _BMD',
            description='Convert a PNG image, or every PNG under a directory, to _BMD '
            '(.png becomes .bmd; other files are copied unchanged).',
        )
        to_bmd.add_argument('input', type=pathlib.Path, help='PNG file or directory')
        to_bmd.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_bmd.set_defaults(func=self.cmd_encode_bmd)

    def cmd_extract(self, args):
        try:
            with DATFile(args.input) as dat:
                dat.extract_all(
                    args.output, glob=getattr(args, 'glob', None), convert_bmd=getattr(args, 'convert_bmd', False)
                )
        except ValueError as e:
            _fail(e)

    def cmd_create(self, args):
        kind = getattr(args, 'kind', None)
        try:
            with DATFile(
                args.output,
                mode='w',
                kind=_KIND_NAMES[kind] if kind else None,
                game_id=getattr(args, 'game_id', None),
                slots=getattr(args, 'slots', None),
            ) as dat:
                dat.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_decode_bmd(self, args):
        _convert_tree(
            args.input,
            args.output,
            is_bmd,
            bmd_to_png,
            lambda p: _swap_suffix(p, '.bmd', '.png'),
            '_BMD image',
        )

    def cmd_encode_bmd(self, args):
        _convert_tree(
            args.input,
            args.output,
            lambda d: d.startswith(_PNG_MAGIC),
            png_to_bmd,
            lambda p: _swap_suffix(p, '.png', '.bmd'),
            'PNG image',
        )
