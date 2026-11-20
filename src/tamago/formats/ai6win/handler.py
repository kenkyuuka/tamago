import sys

from tamago.formats.ai6win.arcfile import ARCFile


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


class AI6WINHandler:
    """Format handler for AI6WIN .arc archives (elf, Silky's).

    ``create`` compresses members as the manifest records, or else by
    extension; ``--compress`` and ``--no-compress`` override this for every
    member.
    """

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        try:
            with ARCFile(args.input) as arc:
                arc.extract_all(args.output, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_create(self, args):
        try:
            with ARCFile(args.output, mode='w', compress=getattr(args, 'compress', None)) as arc:
                arc.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)
