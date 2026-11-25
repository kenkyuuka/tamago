import sys

from tamago.formats.silky.arcfile import ARCFile


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


class SilkyHandler:
    """Format handler for Silky's .arc archives with length-prefixed names (Silky's Sakura).

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
