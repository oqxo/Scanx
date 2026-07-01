"""
scanx.tools.repo_tools
=======================
Step 1 of the workflow: get a local, verified path to the repository.
Either clone a remote URL or validate a user-supplied local path.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import git
from langchain.tools import tool

from scanx.logging_config import get_logger

log = get_logger("tools.repo")


class RepoAcquisitionError(Exception):
    """Raised when we can't obtain or validate a usable repo path."""


@tool
def clone_repo(url: str) -> str:
    """
    Clone a git repository (GitHub/GitLab/etc URL, or SSH remote) into a
    fresh temp folder under the current working directory.

    Args:
        url: The git remote URL to clone.

    Returns:
        The local filesystem path to the cloned repository.

    Raises:
        RepoAcquisitionError: if the clone fails for any reason.
    """
    folder = tempfile.mkdtemp(prefix="scanx_repo_", dir=".")
    log.info("Cloning repository %s -> %s", url, folder)
    try:
        git.Repo.clone_from(url, folder, depth=1)
    except git.GitCommandError as exc:
        shutil.rmtree(folder, ignore_errors=True)
        log.error("Clone failed for %s: %s", url, exc)
        raise RepoAcquisitionError(f"Failed to clone '{url}': {exc}") from exc
    log.info("Clone complete: %s", folder)
    return folder


@tool
def verify_local_path(path: str) -> str:
    """
    Verify that a user-supplied local path exists and is a directory
    that Scanx can scan.

    Args:
        path: Filesystem path supplied by the user.

    Returns:
        The resolved, absolute path as a string.

    Raises:
        RepoAcquisitionError: if the path doesn't exist or isn't a directory.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        log.error("Path does not exist: %s", resolved)
        raise RepoAcquisitionError(f"Path does not exist: {resolved}")
    if not resolved.is_dir():
        log.error("Path is not a directory: %s", resolved)
        raise RepoAcquisitionError(f"Path is not a directory: {resolved}")
    log.info("Verified local path: %s", resolved)
    return str(resolved)


def cleanup_cloned_repo(path: str) -> None:
    """Best-effort cleanup of a temp-cloned repo directory."""
    p = Path(path)
    if p.exists() and p.name.startswith("scanx_repo_"):
        shutil.rmtree(p, ignore_errors=True)
        log.info("Cleaned up temporary clone at %s", p)
