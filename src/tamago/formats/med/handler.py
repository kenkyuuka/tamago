import sys

from tamago.formats.med.medfile import MEDFile


class MEDHandler:
    """Format handler for "MD" archives (.med) used by Fudegaki Soft games."""

    def add_extract_args(self, parser):
        parser.add_argument('--keyword', help='script keyword (default: recovered from the archive\'s _VIEW script)')
        parser.add_argument(
            '--no-decrypt', action='store_false', dest='decrypt', help='extract scripts as stored, still encrypted'
        )
        parser.add_argument(
            '--no-convert-prs',
            dest='convert_prs',
            action='store_false',
            help='keep PRS images as stored instead of converting them to PNG',
        )
        parser.add_argument(
            '--no-convert-wady',
            dest='convert_wady',
            action='store_false',
            help='keep WADY audio as stored instead of converting it to WAV',
        )

    def add_create_args(self, parser):
        parser.add_argument('--keyword', help='encrypt scripts with this keyword (needed for decrypted scripts)')
        parser.add_argument(
            '--signature', help='archive signature, e.g. MDE0, MDE1, MDN6 (default: inferred from the files)'
        )

    def cmd_extract(self, args):
        try:
            with MEDFile(
                args.input, keyword=getattr(args, 'keyword', None), decrypt=getattr(args, 'decrypt', True)
            ) as med:
                if med.is_script_archive and med.decrypt and getattr(args, 'keyword', None) is None:
                    if med.keyword is None:
                        print(
                            f"Error: could not recover the script keyword of {args.input}; "
                            "pass --keyword, or --no-decrypt to extract scripts as stored",
                            file=sys.stderr,
                        )
                        raise SystemExit(1)
                    print(
                        f"Note: {args.input} scripts use keyword {med.keyword!r} "
                        f"(pass --keyword {med.keyword} to recreate it)",
                        file=sys.stderr,
                    )
                med.extract_all(
                    args.output,
                    glob=getattr(args, 'glob', None),
                    convert_prs=getattr(args, 'convert_prs', True),
                    convert_wady=getattr(args, 'convert_wady', True),
                )
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_create(self, args):
        try:
            with MEDFile(
                args.output,
                mode='w',
                keyword=getattr(args, 'keyword', None),
                signature=getattr(args, 'signature', None),
            ) as med:
                med.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None
