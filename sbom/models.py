from dataclasses import dataclass
from pathlib import Path
from typing import Literal

@dataclass(frozen=True) # immutable
class DependencyRecord:
    name: str
    version: str | None # None if no version is specified
    type: Literal["pip", "npm"]
    path: Path
    dev: bool = False # Default: not a dev dependency
    git_commit: str | None = None