from tamago.formats.livemaker.vffile import VFFile


class LiveMakerHandler:
    """Format handler for LiveMaker VF archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        parser.add_argument(
            '--scramble',
            action='store_true',
            help='apply chunk-reorder scrambling to every stored file',
        )

    def cmd_extract(self, args):
        with VFFile(args.input) as arc:
            arc.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        compress = getattr(args, 'compress', None)
        scramble = getattr(args, 'scramble', False)
        with VFFile(args.output, mode='w') as arc:
            arc.write_all(
                args.input,
                glob=getattr(args, 'glob', None),
                compress=compress,
                scramble=scramble,
            )
