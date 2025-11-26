import argparse
import sys
import textwrap
from pathlib import Path

from sbom.scanner import DependencyScanner
from sbom.writer import SBOMWriter

import logging
logger = logging.getLogger(__name__)


class SBOMArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that incorporates colored error messages."""

    def error(self, message: str) -> None:
        """Prints a usage message incorporating the message to stderr and exits.

        Args:
            message (str): The error message to display.

        Raises:
            SystemExit: Always exits the program with status code 2.
        """
        self.print_usage(sys.stderr)
        # ANSI escape code for red text: \033[91m, reset: \033[0m
        self.exit(2, f"\033[91m{self.prog}: error: {message}\033[0m\n")


def existing_dir(path_str: str) -> Path:
    """Validate that a given path string is an existing directory.

    Args:
        path_str (str): The path to validate.

    Raises:
        argparse.ArgumentTypeError: If the path does not exist.
        argparse.ArgumentTypeError: If the path exists but is not a directory.

    Returns:
        pathlib.Path: The validated path as a Path object.
    """
    path = Path(path_str)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Directory does not exist: {path}")
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Not a directory: {path}")
    
    return path


def parse_args() -> argparse.Namespace:
    """Create and parse the command-line arguments for the SBOM tool.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = SBOMArgumentParser(
        description=textwrap.dedent("""
            This tool searches a directory for repositories and makes a
            Software Bill of Materials (SBOM) in both CSV and JSON format,
            documenting the dependencies of all the repositories.
        """).strip()
    )
    parser.add_argument("directory", type=existing_dir, help="Path to the directory containing repositories")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (show DEBUG messages)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress most output (show only WARNING or higher messages)")
    
    return parser.parse_args()


def main(args: argparse.Namespace) -> int:
    try:
        directory = args.directory

        scanner = DependencyScanner(directory)
        deps = scanner.get_dependencies()

        writer = SBOMWriter()
        writer.write_sbom(deps)
        return 0
    except Exception as e:
        logger.error(e)
        return 1
