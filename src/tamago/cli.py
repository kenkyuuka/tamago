import argparse
import importlib.metadata
import pathlib
import sys

from tamago.formats.livemaker.vffile import VF_MAGIC as LIVEMAKER_MAGIC
from tamago.formats.xp3.models import XP3_MAGIC

# Magic bytes used to identify archive formats.
FORMAT_MAGIC = {
    'xp3': XP3_MAGIC,
    'livemaker': LIVEMAKER_MAGIC,
}

# Formats detected by file extension (no magic bytes).
EXTENSION_FORMATS = {
    '.det': 'det',
    '.gsp': 'gsp',
    '.arc': 'advhd',
}


def get_format_handlers():
    """Discover format handlers registered under the ``tamago.formats`` entry point group."""
    handlers = {}
    for ep in importlib.metadata.entry_points(group='tamago.formats'):
        handlers[ep.name] = ep
    return handlers


def _detect_by_extension(path):
    """Return the format name for *path* based on file extension, or ``None``."""
    ext = pathlib.Path(path).suffix.lower()
    return EXTENSION_FORMATS.get(ext)


def detect_format(path):
    """Return the format name for *path* based on magic bytes, or ``None``."""
    try:
        with open(path, 'rb') as f:
            header = f.read(16)
            # LiveMaker exe-embedded archives have a 'lv' trailer at EOF.
            f.seek(0, 2)
            size = f.tell()
            trailer = b''
            if size >= 6:
                f.seek(size - 6)
                trailer = f.read(6)
    except OSError:
        return None
    for name, magic in FORMAT_MAGIC.items():
        if header[: len(magic)] == magic:
            return name
    if trailer.endswith(b'lv') and header[:2] == b'MZ':
        return 'livemaker'
    return _detect_by_extension(path)


def _resolve_handler(fmt, handler_instances):
    """Look up the handler for *fmt*, or exit with an error."""
    if fmt not in handler_instances:
        print(f"Error: no handler installed for format {fmt!r}", file=sys.stderr)
        raise SystemExit(1)
    return handler_instances[fmt]


def cmd_identify(args):
    for path in args.files:
        fmt = detect_format(path)
        if fmt is None:
            print(f"{path}: unknown format")
        else:
            print(f"{path}: {fmt}")


def cmd_extract(args, handler_instances):
    fmt = detect_format(args.input)
    if fmt is None:
        print(f"Error: cannot detect format of {args.input}", file=sys.stderr)
        raise SystemExit(1)
    handler = _resolve_handler(fmt, handler_instances)
    handler.cmd_extract(args)


def cmd_create(args, handler_instances):
    fmt = args.format
    if fmt is None:
        print("Error: --format is required for create", file=sys.stderr)
        raise SystemExit(1)
    handler = _resolve_handler(fmt, handler_instances)
    handler.cmd_create(args)


def main():
    # Discover and instantiate format handlers.
    handler_entries = get_format_handlers()
    handler_instances = {}
    for name, ep in handler_entries.items():
        handler_cls = ep.load()
        handler_instances[name] = handler_cls()

    parser = argparse.ArgumentParser(prog='tamago', description='Multi-format game archive tool.')
    subparsers = parser.add_subparsers(dest='command')

    # identify
    p_identify = subparsers.add_parser('identify', help='Identify archive format by magic bytes')
    p_identify.add_argument('files', nargs='+', type=pathlib.Path, help='Files to identify')
    p_identify.set_defaults(func=cmd_identify)

    # top-level extract (auto-detect format, common flags only)
    p_extract = subparsers.add_parser('extract', help='Extract an archive (auto-detect format)')
    p_extract.add_argument('input', type=pathlib.Path, help='Archive file to extract')
    p_extract.add_argument('output', type=pathlib.Path, help='Output directory')
    p_extract.add_argument('--glob', metavar='PATTERN', help='extract only files matching PATTERN')
    p_extract.set_defaults(func=lambda args: cmd_extract(args, handler_instances))

    # top-level create (requires --format, common flags only)
    p_create = subparsers.add_parser('create', help='Create an archive (requires --format)')
    p_create.add_argument('--format', required=True, help='Archive format (e.g. xp3, det)')
    p_create.add_argument('input', type=pathlib.Path, help='Source directory')
    p_create.add_argument('output', type=pathlib.Path, help='Output archive path')
    p_create.add_argument('--glob', metavar='PATTERN', help='only include files matching PATTERN')
    p_create_compress = p_create.add_mutually_exclusive_group()
    p_create_compress.add_argument('--compress', action='store_true', default=None, help='compress file data')
    p_create_compress.add_argument(
        '--no-compress', action='store_false', dest='compress', help='store file data uncompressed'
    )
    p_create.set_defaults(func=lambda args: cmd_create(args, handler_instances))

    # Format subcommands (e.g. tamago xp3 extract, tamago det create)
    for name, handler in handler_instances.items():
        fmt_parser = subparsers.add_parser(name, help=f'{name} format operations')
        fmt_sub = fmt_parser.add_subparsers(dest='action')

        ext_p = fmt_sub.add_parser('extract', help=f'Extract a {name} archive')
        ext_p.add_argument('input', type=pathlib.Path, help='Archive file to extract')
        ext_p.add_argument('output', type=pathlib.Path, help='Output directory')
        ext_p.add_argument('--glob', metavar='PATTERN', help='extract only files matching PATTERN')
        handler.add_extract_args(ext_p)
        ext_p.set_defaults(func=handler.cmd_extract)

        crt_p = fmt_sub.add_parser('create', help=f'Create a {name} archive')
        crt_p.add_argument('input', type=pathlib.Path, help='Source directory')
        crt_p.add_argument('output', type=pathlib.Path, help='Output archive path')
        crt_p.add_argument('--glob', metavar='PATTERN', help='only include files matching PATTERN')
        crt_compress = crt_p.add_mutually_exclusive_group()
        crt_compress.add_argument('--compress', action='store_true', default=None, help='compress file data')
        crt_compress.add_argument(
            '--no-compress', action='store_false', dest='compress', help='store file data uncompressed'
        )
        handler.add_create_args(crt_p)
        crt_p.set_defaults(func=handler.cmd_create)

    args, remaining = parser.parse_known_args()

    if not hasattr(args, 'func'):
        if remaining:
            # Re-parse to produce proper error messages for unknown args.
            parser.parse_args()
        if args.command and args.command in handler_instances:
            # Format subcommand with no action — show its help.
            subparsers.choices[args.command].print_help()
        else:
            parser.print_help()
        raise SystemExit(0)

    # For top-level create, add format-specific args and re-parse.
    if args.command == 'create' and remaining:
        fmt = args.format
        if fmt and fmt in handler_instances:
            handler_instances[fmt].add_create_args(p_create)
            args = parser.parse_args()
        else:
            # Re-parse to produce proper error messages for unknown args.
            parser.parse_args()
    elif remaining:
        # Re-parse to produce proper error messages for unknown args.
        parser.parse_args()

    args.func(args)
