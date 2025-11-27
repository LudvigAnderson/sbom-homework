from pathlib import Path
import json
import subprocess
import dataclasses

from sbom.models import DependencyRecord

import logging
logger = logging.getLogger(__name__)

class ScanningError(Exception):
    """Base class for all SBOM scanner exceptions"""

class NoRepositoriesFoundError(ScanningError):
    pass

class NoDependenciesFoundError(ScanningError):
    pass

class DependencyScanner:
    """Scans a directory for dependency files and collects dependency information."""
    
    _DEPENDENCY_FILENAMES = [
        "requirements.txt",
        "package.json",
        "package-lock.json"
    ]

    def __init__(self, root_directory: Path | str) -> None:
        """Initialize the scanner with a root directory.

        Args:
            root_directory (Path | str): Path to the root directory to scan.
        """
        self.root_directory = Path(root_directory) # works for both str and Path
        self.dependencies: set[DependencyRecord] | None = None

    def _get_git_commit(self, repo: Path) -> str | None:
        """Return the latest Git commit hash (HEAD) for the given repository.

        Args:
            repo (Path): Path to the repository.

        Returns:
            str | None: Full commit hash, or None if the repository is not
            a Git repo, empty, or Git is not installed.
        """
        try:
            result = subprocess.check_output(
                ["git", "-C", repo, "log", "--format=%H", "-n", "1"],
                stderr=subprocess.STDOUT
            )
            return result.decode().strip()
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git command failed for repo {repo}: {e}")
            return None
        except FileNotFoundError as e:
            logger.warning("Git executable not found. Is Git installed?")
            return None

    def _is_dependency_file(self, entry: Path) -> bool:
        """Check if a file is a recognized dependency file."""
        return entry.name in self._DEPENDENCY_FILENAMES
    
    def _find_dependency_files(self, repo: Path) -> dict[str, Path]:
        """Find dependency files in the given repository."""
        return {entry.name: entry for entry in repo.iterdir() if self._is_dependency_file(entry)}

    def _parse_python_dependencies(self, requirements_txt: Path) -> set[DependencyRecord]:
        """Parse a Python requirements.txt file into dependency records.

        Args:
            requirements_txt (Path): Path to the requirements.txt file.

        Returns:
            set[DependencyRecord]: Set of parsed Python dependencies.
        """
        dependency_set = set()
        operators = ("==", ">=", "<=", "!=", "~=", ">", "<")
        
        with requirements_txt.open() as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

                # for example a line that just says "numpy"
                name = line
                version = None

                for op in operators:
                    if op in line:
                        name, version = line.split(op, 1)
                        name = name.strip()
                        version = op + version # for example ">=1.2"
                        break # operator already found

                dependency_set.add(DependencyRecord(
                    name=name,
                    version=version, 
                    type="pip",
                    path=requirements_txt
                ))
        
        return dependency_set
    
    def _parse_package(self, package: dict, path: Path) -> set[DependencyRecord]:
        """Parse dependencies from a package.json object.

        Args:
            package (dict): Parsed package.json data.
            path (Path): Path to the package.json file.

        Returns:
            set[DependencyRecord]: Set of npm dependencies.
        """
        dependencies = {
            DependencyRecord(
                name=name,
                version=version,
                type="npm",
                path=path,
                dev=False
            )
            for name, version in package["dependencies"].items()
        }
        dev_dependencies = {
            DependencyRecord(
                name=name,
                version=version,
                type="npm",
                path=path,
                dev=True
            )
            for name, version in package.get("devDependencies", {}).items() # default to empty dict
        }
        
        return dependencies | dev_dependencies
    
    def _parse_package_lock_json(self, package_lock_json: Path) -> set[DependencyRecord]:
        """Parse an npm package-lock.json file into dependency records.

        Args:
            package_lock_json (Path): Path to package-lock.json.

        Returns:
            set[DependencyRecord]: Set of npm dependencies.

        Raises:
            NotImplementedError: If lockfileVersion 1 or 2 is encountered.
            ValueError: If lockfileVersion is unsupported.
        """
        with open(package_lock_json, "r", encoding="utf-8") as f:
            data = json.load(f)
            lockfile_version = data["lockfileVersion"]

            if lockfile_version in {1, 2}:
                # CAN PROBABLY IMPLEMENT, FOUND AN EXAMPLE, BOOKMARKED IT
                raise NotImplementedError(f"Parsing of package-lock.json files with lockfileVersion {lockfile_version} is not yet implemented.")
            elif lockfile_version == 3:
                packages = data["packages"]
                return {
                    DependencyRecord(
                        name=name.split("node_modules/")[-1],
                        version=info.get("version"),
                        type="npm",
                        path=package_lock_json,
                        dev=info.get("dev", False)
                    )
                    for name, info in packages.items()
                    if name != ""
                }  
            else:
                raise ValueError(f"Unsupported package-lock.json lockfileVersion: {lockfile_version}")

    def _parse_package_json(self, package_json: Path) -> set[DependencyRecord]:
        """Parse an npm package.json file into dependency records.

        Args:
            package_json (Path): Path to package.json.

        Returns:
            set[DependencyRecord]: Set of npm dependencies.
        """
        with open(package_json, "r", encoding="utf-8") as f:
            data = json.load(f)
            return self._parse_package(package=data, path=package_json)



    
    def _parse_javascript_dependencies(
            self,
            *,
            package_json: Path | None = None,
            package_lock_json: Path | None = None
    ) -> set[DependencyRecord]:
        """Parse JavaScript dependencies from package.json or package-lock.json.

        Prefers parsing package-lock.json if provided.

        Args:
            package_json (Path | None): Optional package.json path.
            package_lock_json (Path | None): Optional package-lock.json path.

        Returns:
            set[DependencyRecord]: Set of JavaScript dependencies.
        """
        if package_lock_json is not None:
            # Prefer parsing package-lock.json
            try:
                return self._parse_package_lock_json(package_lock_json)
            except NotImplementedError:
                logger.warning(f"Parsing of package-lock.json failed due to unsupported lockfileVersion: {package_lock_json}")
        if package_json is not None:
            # Otherwise, parse package.json
            return self._parse_package_json(package_json)
            
    def _scan_repo(self, repo: Path) -> set[DependencyRecord]:
        """Scan a repository for dependency files and parse them.

        Args:
            repo (Path): Path to the repository.

        Returns:
            set[DependencyRecord]: All dependencies found in the repository.
        """
        dependency_files = self._find_dependency_files(repo)
        requirements_txt = dependency_files.get("requirements.txt")
        package_lock_json = dependency_files.get("package-lock.json")
        package_json = dependency_files.get("package.json")


        repo_dependencies = set()

        if requirements_txt:
            python_dependencies = self._parse_python_dependencies(requirements_txt)
            repo_dependencies.update(python_dependencies)
        
        if package_lock_json or package_json:
            javascript_dependencies = self._parse_javascript_dependencies(
                package_json=package_json,
                package_lock_json=package_lock_json
            )
            repo_dependencies.update(javascript_dependencies)
        
        # Add the git commit column to all the dependencies.
        # Need to use dataclasses.replace because DependencyRecord is immutable.
        git_commit = self._get_git_commit(repo)
        return {dataclasses.replace(dep, git_commit=git_commit) for dep in repo_dependencies}

    def scan(self) -> None:
        """Scan all repositories under the root directory for dependencies.

        Raises:
            NoRepositoriesFoundError: If no subdirectories are found.
            NoDependenciesFoundError: If no dependencies are found in any repository.
        """
        repos = [entry for entry in self.root_directory.iterdir() if entry.is_dir()]
        if not repos:
            raise NoRepositoriesFoundError(f"No repositories were found in {self.root_directory}.")

        self.dependencies = set()

        for repo in repos:
            repo_dependencies = self._scan_repo(repo)
            if not repo_dependencies:
                logger.warning(f"No dependencies found in the following repo: {repo}")
                # Consider instead keeping track of the repos and handle it at the end.

            self.dependencies.update(repo_dependencies)

        if not self.dependencies:
            raise NoDependenciesFoundError(f"No dependencies found in repositories in {self.root_directory}.")

    def get_dependencies(self) -> set[DependencyRecord]:
        """Return all dependencies found by the scanner, scanning if necessary.

        Returns:
            set[DependencyRecord]: All dependencies in scanned repositories.
        """
        if self.dependencies is None:
            self.scan()
        
        return self.dependencies