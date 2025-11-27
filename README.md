# sbom-homework

## Requirements

- Python 3.10+ (At least I used 3.11.5)
- Only standard library modules (no external dependencies)

## How to Run

```bash
python sbom.py /path/to/repos/
```

### Arguments
- `/path/to/repos` **(mandatory)**

    Example: `/path/to/repos` is a folder containing folders that represent git repositories.

    ```markdown
    /path/to/repos
    ├─ 📁 repo1
    │   └─ 📄 requirements.txt
    └─ 📁 repo2
        ├─ 📄 package.json
        └─ 📄 package-lock.json
    ```

- `-o, --output-dir` (optional)

    Directory where SBOM files will be saved. If not provided, the current working directory is used.

- `-q, --quiet` (optional)

    Suppress most output (show only WARNING or higher messages).

- `-v, --verbose` (optional)

    Enable verbose output (show DEBUG messages). _But keep in mind that there actually aren't any DEBUG messages..._

## Assumptions
- I couldn't find great documentation about precisely how the package-lock.json files are structured. In particular, I couldn't find any examples of lockfileVersion 2, so I trust the documentation that said it's backwards-compatible with v1. As for v1 and v3, I tried to understand them from examples I found.

## Ideas for Features
- Some repos put their `requirements.txt` and `package.json` inside other folders, so it could be a good idea to do a recursive search for them if they are not found in the root folder.
- To find vulnerabilities, I could use the API of some vulnerability database like Google's OSV: https://google.github.io/osv.dev/api/
- Generate an HTML file that allows for easy filtering and sorting of the SBOM.
- Add support for dependencies for different programming languages.
- Find indirect dependencies for the Python dependencies.