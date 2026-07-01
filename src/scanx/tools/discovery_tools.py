"""
scanx.tools.discovery_tools
=============================
Step 2 of the workflow: walk the repo and produce the exact list of files
that should be sent for analysis.

Two discovery strategies:
  1. Git repos (a `.git` dir is present): shell out to `git ls-files -co
     --exclude-standard`, which is git's own authoritative view of "every
     tracked file, plus untracked files, minus anything .gitignore'd" —
     far more correct than reimplementing gitignore semantics by hand.
  2. Non-git local directories: manual walk + a small hand-rolled gitignore
     matcher (supports comments, blanks, `!` negation, dir-only trailing
     `/`, and glob wildcards via fnmatch), applied per-directory the way
     git itself layers nested .gitignore files.

Both strategies then run through the same deny/allow rules in scanx.config.
"""

from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path

from langchain.tools import tool

from scanx.config import (
    EXCLUDED_DIR_NAME_PREFIXES,
    EXCLUDED_EXTENSIONS,
    EXCLUDED_FILE_NAMES,
    EXTENSIONLESS_ALLOWLIST,
    HIDDEN_DIR_ALLOWLIST,
    INCLUDED_EXTENSIONS,
    ScanConfig,
)
from scanx.logging_config import get_logger

log = get_logger("tools.discovery")


@dataclass
class DiscoveredFile:
    absolute_path: str
    relative_path: str
    size_bytes: int


# --------------------------------------------------------------------------
# Gitignore matcher (fallback for non-git local paths)
# --------------------------------------------------------------------------
class _GitignorePattern:
    __slots__ = ("pattern", "negation", "dir_only", "anchored")

    def __init__(self, raw: str):
        line = raw
        self.negation = line.startswith("!")
        if self.negation:
            line = line[1:]
        self.dir_only = line.endswith("/")
        if self.dir_only:
            line = line[:-1]
        self.anchored = "/" in line.strip("/")
        self.pattern = line

    def matches(self, rel_posix_path: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        name = rel_posix_path.rsplit("/", 1)[-1]
        if self.anchored:
            return fnmatch.fnmatch(rel_posix_path, self.pattern) or fnmatch.fnmatch(
                rel_posix_path, f"*/{self.pattern}"
            )
        return fnmatch.fnmatch(name, self.pattern)


class GitignoreMatcher:
    """Minimal, dependency-free .gitignore matcher, layered per-directory."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self._cache: dict[Path, list[_GitignorePattern]] = {}

    def _patterns_for_dir(self, directory: Path) -> list[_GitignorePattern]:
        if directory in self._cache:
            return self._cache[directory]
        patterns: list[_GitignorePattern] = []
        gitignore_file = directory / ".gitignore"
        if gitignore_file.is_file():
            try:
                for raw_line in gitignore_file.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines():
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    patterns.append(_GitignorePattern(stripped))
            except OSError:
                pass
        self._cache[directory] = patterns
        return patterns

    def is_ignored(self, path: Path, is_dir: bool) -> bool:
        """Check a path against every .gitignore from repo root down to its parent."""
        try:
            rel = path.relative_to(self.repo_root)
        except ValueError:
            return False
        ignored = False
        parts = rel.parts[:-1]
        dirs_to_check = [self.repo_root] + [
            self.repo_root.joinpath(*parts[: i + 1]) for i in range(len(parts))
        ]
        rel_posix = rel.as_posix()
        for d in dirs_to_check:
            for pattern in self._patterns_for_dir(d):
                if pattern.matches(rel_posix, is_dir):
                    ignored = not pattern.negation
        return ignored


# --------------------------------------------------------------------------
# Shared allow/deny logic
# --------------------------------------------------------------------------
def _is_hidden_dir_excluded(dir_name: str) -> bool:
    if not dir_name.startswith("."):
        return False
    return dir_name not in HIDDEN_DIR_ALLOWLIST


def _is_dir_excluded(dir_name: str, config: ScanConfig) -> bool:
    if _is_hidden_dir_excluded(dir_name):
        return True
    if dir_name in config.effective_excluded_dirs():
        return True
    if any(dir_name.startswith(p) for p in EXCLUDED_DIR_NAME_PREFIXES):
        return True
    return False


def _is_file_allowed(file_path: Path, config: ScanConfig) -> bool:
    name_lower = file_path.name.lower()

    # Hidden dotfiles are skipped by default (like hidden dirs), EXCEPT a
    # small allowlist of security-relevant ones. Note: pathlib treats a
    # dotfile's entire name as the stem with an EMPTY suffix (Path(".env").suffix
    # == ""), so these must be matched on full name, not extension.
    if file_path.name.startswith("."):
        if name_lower in {".env", ".env.example", ".env.local", ".env.production"}:
            return True
        return False

    if name_lower in EXCLUDED_FILE_NAMES:
        return False

    suffix = file_path.suffix.lower()
    if suffix in EXCLUDED_EXTENSIONS:
        return False

    if suffix:
        if suffix not in INCLUDED_EXTENSIONS:
            return False
    else:
        if name_lower not in EXTENSIONLESS_ALLOWLIST:
            return False

    return True


def _is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


def _git_tracked_and_untracked_files(root: Path) -> list[str] | None:
    """Use git's own logic for 'everything not gitignored'. Returns None on failure."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        log.warning("git ls-files failed (%s); falling back to manual walk.", exc)
        return None
    return [line for line in result.stdout.splitlines() if line.strip()]


def discover_files_impl(repo_root: str, config: ScanConfig) -> list[DiscoveredFile]:
    """Core discovery logic, callable directly (not just as a LangChain tool)."""
    root = Path(repo_root).resolve()
    discovered: list[DiscoveredFile] = []

    if _is_git_repo(root):
        rel_paths = _git_tracked_and_untracked_files(root)
    else:
        rel_paths = None

    if rel_paths is not None:
        log.info("Using git-native file listing (respects .gitignore exactly).")
        for rel in rel_paths:
            abs_path = root / rel
            if not abs_path.is_file():
                continue
            # Directory-name exclusions still apply even to git-tracked files
            # (e.g. a stray node_modules/ file someone force-added).
            if any(_is_dir_excluded(part, config) for part in abs_path.relative_to(root).parts[:-1]):
                continue
            if not _is_file_allowed(abs_path, config):
                continue
            try:
                size = abs_path.stat().st_size
            except OSError:
                continue
            if size > config.max_file_bytes or size == 0:
                continue
            discovered.append(
                DiscoveredFile(
                    absolute_path=str(abs_path),
                    relative_path=abs_path.relative_to(root).as_posix(),
                    size_bytes=size,
                )
            )
    else:
        log.info("Using manual walk + hand-rolled .gitignore matcher.")
        matcher = GitignoreMatcher(root)
        for dirpath, dirnames, filenames in _walk(root, config, matcher):
            for fname in filenames:
                abs_path = Path(dirpath) / fname
                if matcher.is_ignored(abs_path, is_dir=False):
                    continue
                if not _is_file_allowed(abs_path, config):
                    continue
                try:
                    size = abs_path.stat().st_size
                except OSError:
                    continue
                if size > config.max_file_bytes or size == 0:
                    continue
                discovered.append(
                    DiscoveredFile(
                        absolute_path=str(abs_path),
                        relative_path=abs_path.relative_to(root).as_posix(),
                        size_bytes=size,
                    )
                )

    log.info("Discovery complete: %d files selected for scanning.", len(discovered))
    return discovered


def _walk(root: Path, config: ScanConfig, matcher: GitignoreMatcher):
    """os.walk-style generator that prunes excluded directories in place."""
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [
            d
            for d in dirnames
            if not _is_dir_excluded(d, config) and not matcher.is_ignored(current / d, is_dir=True)
        ]
        yield dirpath, dirnames, filenames


@tool
def discover_files(repo_root: str) -> list[str]:
    """
    Walk a repository and return the relative paths of every file that
    should be sent for security analysis, after applying the exclusion
    policy (build/vendor/test/doc dirs, lockfiles, binaries, .gitignore).

    Args:
        repo_root: Absolute local path to the repository root.

    Returns:
        List of relative file paths selected for scanning.
    """
    config = ScanConfig()
    files = discover_files_impl(repo_root, config)
    return [f.relative_path for f in files]
