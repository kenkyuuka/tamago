import argparse

from tamago.formats.rpa.rpafile import DEFAULT_KEY, MAX_KEY, RPAFile


def _parse_key(text):
    try:
        key = int(text, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a hexadecimal key: {text!r}") from None
    if not 0 <= key <= MAX_KEY:
        raise argparse.ArgumentTypeError(f"key does not fit in 32 bits: {text!r}")
    return key


class RPAHandler:
    """Format handler for Ren'Py RPA archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        parser.add_argument(
            '--key',
            type=_parse_key,
            default=DEFAULT_KEY,
            help=f'XOR key for the archive index, in hexadecimal (default: {DEFAULT_KEY:08x})',
        )

    def cmd_extract(self, args):
        with RPAFile(args.input) as rpa:
            rpa.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        with RPAFile(args.output, mode='w', key=getattr(args, 'key', DEFAULT_KEY)) as rpa:
            rpa.write_all(args.input, glob=getattr(args, 'glob', None))
