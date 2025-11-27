from pathlib import Path
from dataclasses import asdict, fields
from typing import Iterable
import csv
import json

from sbom.models import DependencyRecord

import logging
logger = logging.getLogger(__name__)


class SBOMWriter:
    """Writes a Software Bill of Materials (SBOM) in CSV and JSON formats."""
    def __init__(self, output_dir: Path | str | None = None):
        """Initialize an SBOMWriter.

        Args:
            output_dir (Path | str | None): Directory where SBOM files will be written.
                Defaults to the current working directory if None.
        """
        # Default to the current working directory
        self.output_dir = Path(output_dir or Path.cwd()) # works for both str and Path

    def _resolve_output_dir(self, output_dir: Path | None) -> Path:
        """Resolve the output directory, ensuring it exists."""
        dir_path = Path(output_dir or self.output_dir)
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def _resolve_filepath(self, filename: str, output_dir: Path | None = None) -> Path:
        """Return full path for a given filename inside the output directory."""
        dir_path = self._resolve_output_dir(output_dir)
        return dir_path / filename
    
    @staticmethod
    def _serialize_dependency(dep: DependencyRecord) -> dict:
        """Convert a DependencyRecord to a dict suitable for CSV/JSON output."""
        data = asdict(dep)
        data["path"] = str(data["path"])  # normalize Path to string
        return data

    def write_csv(
            self,
            dependencies: Iterable[DependencyRecord],
            output_dir: Path | None = None
    ) -> None:
        """Write the given dependencies to a CSV file named 'sbom.csv'.

        The CSV columns correspond to the fields of DependencyRecord. Rows
        are sorted alphabetically by dependency name for deterministic output.

        Args:
            dependencies (Iterable[DependencyRecord]): Dependencies to write.
            output_dir (Path | None): Optional directory to override the default.
        """
        filepath = self._resolve_filepath("sbom.csv", output_dir)
        logger.info(f"Writing CSV SBOM to {filepath.absolute()}")

        fieldnames = [f.name for f in fields(DependencyRecord)]

        with filepath.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for dep in sorted(dependencies, key=lambda d: d.name):
                row = self._serialize_dependency(dep)
                writer.writerow(row)

    def write_json(
            self,
            dependencies: Iterable[DependencyRecord],
            output_dir: Path | None = None
    ) -> None:
        """Write the given dependencies to a JSON file named 'sbom.json'.

        The output is a list of serialized dependency objects, sorted
        alphabetically by dependency name for deterministic output.

        Args:
            dependencies (Iterable[DependencyRecord]): Dependencies to write.
            output_dir (Path | None): Optional directory to override the default.
        """
        filepath = self._resolve_filepath("sbom.json", output_dir)
        logger.info(f"Writing JSON SBOM to {filepath}")

        data = [self._serialize_dependency(dep) for dep in sorted(dependencies, key=lambda d: d.name)]
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        


    def write_sbom(
            self,
            dependencies: Iterable[DependencyRecord],
            output_dir: Path | None = None
    ) -> None:
        """Write the SBOM in both CSV and JSON formats.

        Args:
            dependencies (Iterable[DependencyRecord]): Dependencies to write.
            output_dir (Path | None): Optional directory to override the default.
        """
        self.write_csv(dependencies, output_dir)
        self.write_json(dependencies, output_dir)