"""File filtering rules for Phase 4 Passive Ingestion (Git Hooks & Watchdog).

Filters out:
  1. Lockfiles (uv.lock, package-lock.json, Cargo.lock, *.lock, *.lockb, etc.)
  2. Git directory internals (.git, .git/**)
  3. Build artifacts, bytecode, temporary files, and runtime caches.
"""

from pathlib import Path

# Exact filenames of dependency lockfiles
EXACT_LOCKFILES: frozenset[str] = frozenset(
    {
        "uv.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.lock",
        "poetry.lock",
        "gemfile.lock",
        "composer.lock",
        "pipfile.lock",
        "packages.lock.json",
        "flake.lock",
        "mix.lock",
        "pubspec.lock",
        "gradle.lockfile",
    }
)

# Lockfile extensions
LOCKFILE_EXTENSIONS: frozenset[str] = frozenset({".lock", ".lockb"})

# Build artifact, cache, and virtual environment directory names
IGNORED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "env",
        ".env",
        "dist",
        "build",
        "target",
        "out",
        "bin",
        "obj",
        ".tox",
        ".nox",
        ".turbo",
        ".next",
        ".nuxt",
        ".gradle",
        ".idea",
        ".vscode",
        ".coverage",
        "htmlcov",
        ".eggs",
        "coverage",
    }
)

# File extensions for compiled code, binary artifacts, and transient editor files
IGNORED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Compiled Python
        ".pyc",
        ".pyo",
        ".pyd",
        # Native libraries and binaries
        ".so",
        ".dll",
        ".dylib",
        ".o",
        ".obj",
        ".a",
        ".lib",
        ".exe",
        ".bin",
        # Packages
        ".whl",
        ".egg",
        ".class",
        ".jar",
        ".war",
        # Temporary & editor swap files
        ".swp",
        ".swo",
        ".tmp",
        ".bak",
        ".ds_store",
        # Database files to prevent recursive ingestion
        ".db",
        ".db-wal",
        ".db-shm",
        ".kuzu",
    }
)


def is_ignored_path(path: str | Path) -> bool:
    """Determine whether a file or directory path should be filtered out from passive capture.

    Returns True if the path represents a lockfile, .git internal, build artifact,
    binary object, or temporary cache file.
    """
    p = Path(path)
    parts = p.parts

    # 1. Check directory path segments (.git, node_modules, __pycache__, .venv, dist, build, etc.)
    for part in parts[:-1]:
        part_lower = part.lower()
        if part_lower in IGNORED_DIR_NAMES or part_lower.endswith(".egg-info"):
            return True
        if part_lower.startswith(".git"):
            return True

    # 2. Check filename / leaf directory
    leaf = p.name.lower()
    if not leaf:
        return False

    if leaf in IGNORED_DIR_NAMES or leaf.endswith(".egg-info") or leaf.startswith(".git"):
        return True

    # 3. Check lockfiles
    if leaf in EXACT_LOCKFILES:
        return True

    suffix = p.suffix.lower()
    if suffix in LOCKFILE_EXTENSIONS:
        return True

    # 4. Check build artifacts and compiled extensions
    if suffix in IGNORED_EXTENSIONS:
        return True

    # 5. Check editor backups and temporary markers
    if leaf.startswith(".#") or leaf.endswith("~") or leaf in ("thumbs.db", ".ds_store"):
        return True

    return False


def filter_file_paths(paths: list[str | Path]) -> list[str]:
    """Filter a list of file paths, removing lockfiles, .git internals, and build artifacts.

    Returns a clean list of string paths.
    """
    clean_paths: list[str] = []
    for p in paths:
        str_path = str(p)
        if not is_ignored_path(str_path):
            clean_paths.append(str_path)
    return clean_paths
