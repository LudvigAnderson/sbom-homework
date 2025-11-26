import sys
import logging
from sbom.cli import parse_args, main as start_cli

def main():
    args = parse_args()
    if args.quiet:
        logging_level = logging.WARNING
    elif args.verbose:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(
        level=logging_level,
        format="%(asctime)s %(levelname)s [%(name)s]: %(message)s"
    )

    exit_code = start_cli(args)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()