import sys

from tamago.formats.scumm.hefile import HEFile


def _fail(message) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


class SCUMMHandler:
    """Format handler for SCUMM resource files (Humongous Entertainment games). Extraction only."""

    def add_extract_args(self, parser):
        parser.add_argument(
            '--no-convert',
            dest='convert',
            action='store_false',
            help='write every block as stored instead of converting sounds to WAV and images to PNG',
        )
        parser.add_argument(
            '--no-index',
            dest='use_index',
            action='store_false',
            help='name room resources by position instead of by the numbers in the .he0 index beside the file',
        )

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        try:
            with HEFile(args.input, use_index=getattr(args, 'use_index', True)) as he:
                he.extract_all(args.output, glob=getattr(args, 'glob', None), convert=getattr(args, 'convert', True))
        except (OSError, ValueError) as e:
            _fail(e)

    def cmd_create(self, args):
        _fail("creating SCUMM resource files is not supported; tamago can only extract them")
