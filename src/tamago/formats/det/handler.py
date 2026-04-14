from tamago.formats.det.detfile import DETFile


class DETHandler:
    """Format handler for μ-GameOperationSystem DET archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        parser.add_argument(
            '--index-format',
            choices=('atm', 'at2'),
            required=True,
            help='index file format for archive creation',
        )

    def cmd_extract(self, args):
        with DETFile(args.input) as det:
            det.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        index_format = getattr(args, 'index_format', None)
        compressed = getattr(args, 'compress', None)
        if compressed is None:
            compressed = False
        with DETFile(args.output, mode='w', index_format=index_format, compressed=compressed) as det:
            det.write_all(args.input, glob=getattr(args, 'glob', None) or '*')
