import sys

from tamago.formats.pfs.pfsfile import ENCODINGS, VERSIONS, PFSFile


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


class PFSHandler:
    """Format handler for Artemis Engine .pfs archives (versions 2, 6 and 8).

    ``create`` follows the extraction manifest's data order, version and
    name encoding; without one it writes a version 8 (encrypted) archive with
    cp932 names.  ``--version`` and ``--encoding`` override either.
    """

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        parser.add_argument(
            '--version',
            dest='pfs_version',
            type=int,
            choices=VERSIONS,
            help='archive version (default: as the manifest records, else 8; only 8 is encrypted)',
        )
        parser.add_argument(
            '--encoding',
            dest='pfs_encoding',
            choices=ENCODINGS,
            help='encoding of member names (default: as the manifest records, else cp932)',
        )

    def cmd_extract(self, args):
        try:
            with PFSFile(args.input) as arc:
                arc.extract_all(args.output, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_create(self, args):
        if getattr(args, 'compress', None):
            _fail("PFS archives store members uncompressed")
        try:
            with PFSFile(
                args.output,
                mode='w',
                version=getattr(args, 'pfs_version', None),
                encoding=getattr(args, 'pfs_encoding', None),
            ) as arc:
                arc.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)
