import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from contextlib import contextmanager
from typing import TypeAlias, Union, Iterator

from sbom.models import DependencyRecord
from sbom.scanner import DependencyScanner, NoDependenciesFoundError

FileStructure: TypeAlias = dict[str, Union[str, "FileStructure"]]

class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        # This turns off warning logging, because otherwise,
        # a warning about missing git commit will be logged for every test.
        patcher = patch("sbom.scanner.logger.warning")
        self.mock_logger = patcher.start()
        self.addCleanup(patcher.stop)

    @contextmanager
    def _create_temp_fs(self, structure: FileStructure) -> Iterator[Path]:
        """Create a temporary file/folder structure for testing.

        Args:
            structure (FileStructure): Nested dict representing files/folders.

        Yields:
            Path: Path to the root temporary directory.
        """
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)

            def _create(current_path: Path, struct: FileStructure):
                for name, value in struct.items():
                    path = current_path / name
                    if isinstance(value, dict):
                        path.mkdir(parents=True, exist_ok=True)
                        _create(path, value)
                    else:
                        path.write_text(value)
            
            _create(root, structure)
            yield root
        
    def _get_dependencies_from_structure(self, structure: FileStructure) -> list[DependencyRecord]:
        """Helper that builds a temp FS and returns sorted dependencies."""
        with self._create_temp_fs(structure) as tmp:
            scanner = DependencyScanner(tmp)
            deps = scanner.get_dependencies()
            return sorted(deps, key=lambda d: d.name)      

    def test_reads_single_line_requirements(self):
        """Scanner correctly reads a single dependency from requirements.txt."""        
        deps = self._get_dependencies_from_structure({
            "repo1": {"requirements.txt": "flask"}
        })

        self.assertEqual(len(deps), 1)
        self.assertIsInstance(deps[0], DependencyRecord)
        self.assertEqual(deps[0].name, "flask")
    
    def test_reads_multiple_lines_requirements(self):
        """Scanner correctly reads multiple dependencies from requirements.txt."""
        deps = self._get_dependencies_from_structure({
            "repo1": {"requirements.txt": "flask\nrequests==3.23.1\nnumpy"}
        })

        self.assertEqual(len(deps), 3)

        for dep in deps:
            self.assertIsInstance(dep, DependencyRecord)

        for dep in deps:
            if dep.name in {"flask", "numpy"}:
                self.assertIsNone(dep.version)
            elif dep.name == "requests":
                self.assertEqual(dep.version, "==3.23.1")

    def test_ignores_commented_lines(self):
        """Lines starting with # are ignored."""
        deps = self._get_dependencies_from_structure({
            "repo1": {"requirements.txt": "flask\n#requests==3.23.1\nnumpy"}
        })

        self.assertEqual(len(deps), 2)
        dep_names = {dep.name for dep in deps}
        self.assertEqual(dep_names, {"flask", "numpy"})
    
    def test_reads_multiple_repos(self):
        """Scanner correctly reads dependencies from multiple repos."""
        deps = self._get_dependencies_from_structure({
            "repo1": {"requirements.txt": "flask\nnumpy"},
            "repo2": {"requirements.txt": "xgboost>=1.0.5\n"}
        })

        self.assertEqual(len(deps), 3)
        dep_names = {dep.name for dep in deps}
        self.assertEqual(dep_names, {"flask", "numpy", "xgboost"})

    def test_empty_requirements_file(self):
        """Empty requirements.txt produces no dependencies."""
        deps = self._get_dependencies_from_structure({
            "repo1": {"requirements.txt": "flask\nnumpy~=1.2"},
            "repo2": {"requirements.txt": ""}
        })

        self.assertEqual(len(deps), 2)
        dep_names = {dep.name for dep in deps}
        self.assertEqual(dep_names, {"flask", "numpy"})

    def test_raises_no_deps_found(self):
        """No dependencies raises an appropriate error."""
        with self.assertRaises(NoDependenciesFoundError):
            self._get_dependencies_from_structure({
                "repo1": {"requirements.txt": ""}
            })

    def test_reads_simple_package_json(self):
        """Scanner reads dependencies from a simple package.json"""
        deps = self._get_dependencies_from_structure({
            "repo1": {
                "package.json": """{
                    "name": "myproject",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "^4.18.2",
                        "lodash": "~4.17.21"
                    }
                }"""
            }
        })

        dep_names = {d.name for d in deps}
        self.assertEqual(dep_names, {"express", "lodash"})

        for dep in deps:
            if dep.name == "express":
                self.assertEqual(dep.version, "^4.18.2")
            elif dep.name == "lodash":
                self.assertEqual(dep.version, "~4.17.21")
    
    def test_reads_both_requirements_and_package(self):
        """Scanner reads dependencies from both python and javascript projects."""
        deps = self._get_dependencies_from_structure({
            "repo1": {
                "package.json": """{
                    "name": "myproject",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "^4.18.2",
                        "lodash": "~4.17.21"
                    }
                }"""
            },
            "repo2": {"requirements.txt": "django\nscikit-learn"}
        })

        dep_names = {d.name for d in deps}
        self.assertEqual(dep_names, {"express", "lodash", "django", "scikit-learn"})

        for dep in deps:
            if dep.name in {"express", "lodash"}:
                self.assertEqual(dep.type, "npm")
            elif dep.name in {"django", "scikit-learn"}:
                self.assertEqual(dep.type, "pip")

    def test_reads_package_lock_1(self):
        """Scanner reads dependencies from a package-lock.json file with lockfileVersion 1.
        
        Because v2 is backwards-compatible with v1, this test is valid for v2 as well.
        """
        deps = self._get_dependencies_from_structure({
            "repo1": {
                "package-lock.json": """{
                    "name": "test-package",
                    "version": "0.0.2",
                    "lockfileVersion": 1,
                    "requires": true,
                    "dependencies": {
                        "@dev-tools/testing": {
                            "version": "7.5.5",
                            "dev": true
                        },
                        "some-dep": {
                            "version": "6.1.0",
                            "dependencies": {
                                "recursive-dep": {
                                    "version": "4.12.1"
                                }
                            }
                        }
                    }
                }"""
            }
        })

        dep_names = {d.name for d in deps}
        self.assertEqual(dep_names, {"@dev-tools/testing", "some-dep", "recursive-dep"})

        for dep in deps:
            if dep.name == "@dev-tools/testing":
                self.assertEqual(dep.version, "7.5.5")
                self.assertTrue(dep.dev)
            elif dep.name == "some-dep":
                self.assertEqual(dep.version, "6.1.0")
                self.assertFalse(dep.dev)
            elif dep.name == "recursive-dep":
                self.assertEqual(dep.version, "4.12.1")
                self.assertFalse(dep.dev)
    
    def test_reads_package_lock_3(self):
        """Scanner reads dependencies from a package-lock.json file with lockfileVersion 3."""
        deps = self._get_dependencies_from_structure({
            "repo1": {
                "package-lock.json": """{
                    "name": "test-package",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "requires": true,
                    "packages": {
                        "": {
                            "name": "test-package",
                            "version": "1.0.0",
                            "dependencies": {
                                "some-or-other-dep": "1.2.3"
                            },
                            "devDependencies": {
                                "a-dev-dep": "2.3.4"
                            }
                        },
                        "node_modules/some-or-other-dep": {
                            "version": "1.2.3",
                            "dependencies": {
                                "recursive-dep": "0.9.21"
                            }
                        },
                        "node_modules/some-or-other-dep/node_modules/recursive-dep": {
                            "version": "0.9.21"
                        },
                        "node_modules/a-dev-dep": {
                            "version": "2.3.4",
                            "dev": true
                        }
                    }
                }"""
            }
        })

        dep_names = {d.name for d in deps}
        self.assertEqual(dep_names, {"some-or-other-dep", "recursive-dep", "a-dev-dep"})

        for dep in deps:
            if dep.name == "some-or-other-dep":
                self.assertEqual(dep.version, "1.2.3")
                self.assertFalse(dep.dev)
            elif dep.name == "recursive-dep":
                self.assertEqual(dep.version, "0.9.21")
                self.assertFalse(dep.dev)
            elif dep.name == "a-dev-dep":
                self.assertEqual(dep.version, "2.3.4")
                self.assertTrue(dep.dev)

    def test_get_git_commit_mocked(self):
        """Returns a fake commit hash using a mock."""
        tmp = Path("/fake/repo")  # any path works, doesn’t have to exist
        scanner = DependencyScanner(tmp)

        # make subprocess.check_output output a predetermined string
        fake_output = b"abcdef1234567890abcdef1234567890abcdef12\n"
        with patch("subprocess.check_output", return_value=fake_output) as mock_sub:
            commit = scanner._get_git_commit(tmp)
            mock_sub.assert_called_once_with(
                ["git", "-C", tmp, "log", "--format=%H", "-n", "1"],
                stderr=subprocess.STDOUT
            )

            deps = self._get_dependencies_from_structure({
                "repo1": {"requirements.txt": "flask"}
            })
            dep = next(iter(deps))

        self.assertEqual(dep.git_commit, "abcdef1234567890abcdef1234567890abcdef12")
        self.assertEqual(commit, "abcdef1234567890abcdef1234567890abcdef12")