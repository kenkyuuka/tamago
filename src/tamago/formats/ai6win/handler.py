import os
import pathlib
import sys

from tamago.formats.ai6win.akb import INCREMENTAL_MAGIC, akb_to_png, is_akb, png_to_akb
from tamago.formats.ai6win.arcfile import ARCFile

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


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


def _is_plain_akb(data: bytes) -> bool:
    return is_akb(data) and data[:4] != INCREMENTAL_MAGIC


class AI6WINHandler:
    """Format handler for AI6WIN .arc archives (elf, Silky's) and AKB images.

    ``create`` compresses members as the manifest records, or else by
    extension; ``--compress`` and ``--no-compress`` override this for every
    member.  PNG files are encoded as AKB images.
    """

    def add_extract_args(self, parser):
        parser.add_argument(
            '--convert-akb',
            action='store_true',
            help='write AKB images as PNG files (create converts them back)',
        )

    def add_create_args(self, parser):
        pass

    def add_commands(self, subparsers):
        """Add ``decode-akb`` and ``encode-akb`` for converting AKB images."""
        to_png = subparsers.add_parser(
            'decode-akb',
            help='Convert AKB images to PNG',
            description='Convert an AKB image, or every AKB under a directory, to PNG '
            '(.akb becomes .png; other files, and incremental AKB+ images, are copied unchanged).',
        )
        to_png.add_argument('input', type=pathlib.Path, help='AKB file or directory')
        to_png.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_png.set_defaults(func=self.cmd_decode_akb)

        to_akb = subparsers.add_parser(
            'encode-akb',
            help='Convert PNG images to AKB',
            description='Convert a PNG image, or every PNG under a directory, to AKB '
            '(.png becomes .akb; other files are copied unchanged).',
        )
        to_akb.add_argument('input', type=pathlib.Path, help='PNG file or directory')
        to_akb.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_akb.set_defaults(func=self.cmd_encode_akb)

    def cmd_extract(self, args):
        try:
            with ARCFile(args.input) as arc:
                arc.extract_all(
                    args.output, glob=getattr(args, 'glob', None), convert_akb=getattr(args, 'convert_akb', False)
                )
        except ValueError as e:
            _fail(e)

    def cmd_create(self, args):
        try:
            with ARCFile(args.output, mode='w', compress=getattr(args, 'compress', None)) as arc:
                arc.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_decode_akb(self, args):
        _convert_tree(
            args.input,
            args.output,
            _is_plain_akb,
            akb_to_png,
            lambda p: _swap_suffix(p, '.akb', '.png'),
            'decodable AKB image',
        )

    def cmd_encode_akb(self, args):
        _convert_tree(
            args.input,
            args.output,
            lambda d: d.startswith(_PNG_MAGIC),
            png_to_akb,
            lambda p: _swap_suffix(p, '.png', '.akb'),
            'PNG image',
        )
