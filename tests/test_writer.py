import unittest
import tempfile
from pathlib import Path
import csv
import json

from sbom.writer import SBOMWriter
from sbom.models import DependencyRecord

class TestSBOMWriter(unittest.TestCase):
    def setUp(self):
        self.dependencies: set[DependencyRecord] = {
            DependencyRecord(name="flask", version="==2.3.2", type="pip", path=Path("/tmp/repo1/requirements.txt")),
            DependencyRecord(name="normal-dep", version=None, type="npm", path=Path("/tmp/repo2/package.json")),
            DependencyRecord(name="dev-dep", version="1.1.1", type="npm", path=Path("/tmp/repo3/package-lock.json"), dev=True)
        }
    
    def test_write_csv_creates_file_with_correct_content(self):
        """CSV file is created and contains all dependencies with correct fields."""
        with tempfile.TemporaryDirectory() as root_dir:
            writer = SBOMWriter(root_dir)
            writer.write_csv(self.dependencies)

            csv_file = Path(root_dir) / "sbom.csv"
            self.assertTrue(csv_file.exists())

            # Read the CSV back and check content
            with csv_file.open() as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), len(self.dependencies))

                names = {row["name"] for row in rows}
                self.assertEqual(names, {"flask", "normal-dep", "dev-dep"})

                # Check that the path is stored as a string
                for row in rows:
                    self.assertIsInstance(row["path"], str)
                
                # Check that version=None gets stored as an empty string
                for row in rows:
                    if row["name"] == "normal-dep":
                        self.assertEqual(row["version"], "")

    def test_write_json_creates_file_with_correct_content(self):
        """JSON file is created and contains all dependencies with correct fields and types."""
        with tempfile.TemporaryDirectory() as root_dir:
            writer = SBOMWriter(root_dir)
            writer.write_json(self.dependencies)

            json_file = Path(root_dir) / "sbom.json"
            self.assertTrue(json_file.exists())

            # Read the JSON back
            with json_file.open() as f:
                data = json.load(f)
                self.assertEqual(len(data), len(self.dependencies))

                names = {item["name"] for item in data}
                self.assertEqual(names, {"flask", "normal-dep", "dev-dep"})

                for item in data:
                    # path should always be string
                    self.assertIsInstance(item["path"], str)

                    # version should match original, converting None to null in JSON
                    if item["name"] == "flask":
                        self.assertEqual(item["version"], "==2.3.2")
                    elif item["name"] == "normal-dep":
                        self.assertIsNone(item["version"])
                    elif item["name"] == "dev-dep":
                        self.assertEqual(item["version"], "1.1.1")

                    # dev flag should be preserved
                    if item["name"] == "dev-dep":
                        self.assertTrue(item["dev"])
                    else:
                        self.assertFalse(item.get("dev", False))
    
    def test_write_sbom_writes_both_csv_and_json(self):
        """write_sbom creates both CSV and JSON files in the target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = SBOMWriter(tmpdir)
            writer.write_sbom(self.dependencies)

            self.assertTrue((Path(tmpdir) / "sbom.csv").exists())
            self.assertTrue((Path(tmpdir) / "sbom.json").exists())