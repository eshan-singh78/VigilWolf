"""Snapshot storage manager for captured HTML artifacts.

Path traversal defense: domain_id and snapshot_id are sanitized and the
resolved path is verified to be within the base snapshots directory.
"""
from __future__ import annotations

import re
from pathlib import Path

import config

# Base directory for all snapshots
_SNAPSHOTS_BASE = Path(config.MONITORING_DATA_DIR) / "snapshots"

# Only allow alphanumeric, hyphens, underscores, and dots in path components
_SAFE_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _sanitize_path_component(value: str, label: str) -> str:
    """Validate a path component to prevent directory traversal.

    Rejects components containing path separators, dots that could form
    traversal sequences, or other unsafe characters.
    """
    if not value:
        raise ValueError(f"{label} must not be empty")
    if not _SAFE_COMPONENT_RE.match(value):
        raise ValueError(
            f"Invalid {label}: {value!r}. Only alphanumeric characters, "
            "hyphens, underscores, and dots are allowed."
        )
    # Block names that look like traversal even after regex (defense in depth)
    if ".." in value or "/" in value or "\\" in value or value == ".":
        raise ValueError(f"Invalid {label}: {value!r} contains forbidden sequence")
    return value


def save_snapshot(domain_id: str, snapshot_id: str, html: str) -> dict:
    """Persist snapshot HTML under MONITORING_DATA_DIR and return paths.

    Raises ValueError if domain_id or snapshot_id contain path traversal
    sequences or unsafe characters.
    """
    safe_domain = _sanitize_path_component(domain_id, "domain_id")
    safe_snapshot = _sanitize_path_component(snapshot_id, "snapshot_id")

    root = _SNAPSHOTS_BASE / safe_domain / safe_snapshot

    # Defense in depth: verify the resolved path is within the base directory
    try:
        root.resolve().relative_to(_SNAPSHOTS_BASE.resolve())
    except ValueError:
        raise ValueError(
            f"Path traversal detected: resolved path {root.resolve()} "
            f"is outside snapshots directory {_SNAPSHOTS_BASE.resolve()}"
        )

    root.mkdir(parents=True, exist_ok=True)
    html_path = root / "page.html"

    # Atomic write: write to temp file then rename
    tmp_path = html_path.with_suffix(".html.tmp")
    try:
        tmp_path.write_text(html, encoding="utf-8", errors="replace")
        tmp_path.rename(html_path)
    except Exception:
        # Clean up temp file on failure
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    return {"html_path": str(html_path), "assets_dir": str(root)}


def load_snapshot(domain_id: str, snapshot_id: str) -> str:
    """Load snapshot HTML from disk.

    Reads the HTML file stored by ``save_snapshot`` and returns the content
    as a string.  Raises ``FileNotFoundError`` if the HTML file does not exist,
    or ``ValueError`` if domain_id or snapshot_id contain unsafe characters.

    Args:
        domain_id: The domain ID used when saving the snapshot.
        snapshot_id: The snapshot ID used when saving the snapshot.

    Returns:
        The HTML content of the snapshot.
    """
    safe_domain = _sanitize_path_component(domain_id, "domain_id")
    safe_snapshot = _sanitize_path_component(snapshot_id, "snapshot_id")

    html_path = _SNAPSHOTS_BASE / safe_domain / safe_snapshot / "page.html"

    # Defense in depth: verify the resolved path is within the base directory
    try:
        html_path.resolve().relative_to(_SNAPSHOTS_BASE.resolve())
    except ValueError:
        raise ValueError(
            f"Path traversal detected: resolved path {html_path.resolve()} "
            f"is outside snapshots directory {_SNAPSHOTS_BASE.resolve()}"
        )

    if not html_path.exists():
        raise FileNotFoundError(
            f"Snapshot HTML not found at {html_path} for "
            f"domain_id={domain_id} snapshot_id={snapshot_id}"
        )

    return html_path.read_text(encoding="utf-8", errors="replace")