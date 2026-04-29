"""NRD (Newly Registered Domains) service — dump management and search."""
import os
import glob
import logging
from datetime import datetime, timezone

from config import MONITORING_DATA_DIR

logger = logging.getLogger(__name__)

NRD_DIR = os.path.join(MONITORING_DATA_DIR, "nrd-file-dump")


def list_nrd_dumps() -> list[dict]:
    """List all NRD dump files with metadata."""
    os.makedirs(NRD_DIR, exist_ok=True)
    dumps = []
    for filepath in sorted(glob.glob(os.path.join(NRD_DIR, "*.txt"))):
        stat = os.stat(filepath)
        filename = os.path.basename(filepath)
        # Count lines (domains) in the file
        domain_count = 0
        try:
            with open(filepath, "r") as f:
                domain_count = sum(1 for _ in f)
        except Exception:
            pass
        dumps.append({
            "filename": filename,
            "date": filename.split("_")[1].split(".")[0] if "_" in filename else filename,
            "domain_count": domain_count,
            "size_bytes": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return dumps


def search_nrd_dumps(query: str, limit: int = 50) -> list[dict]:
    """Search across NRD dump files for matching domains."""
    results = []
    query_lower = query.lower()
    os.makedirs(NRD_DIR, exist_ok=True)
    for filepath in sorted(glob.glob(os.path.join(NRD_DIR, "*.txt"))):
        filename = os.path.basename(filepath)
        try:
            with open(filepath, "r") as f:
                for line in f:
                    domain = line.strip().lower()
                    if query_lower in domain:
                        results.append({"domain": domain, "source": filename})
                        if len(results) >= limit:
                            return results
        except Exception:
            continue
    return results


def get_nrd_stats() -> dict:
    """Get NRD statistics."""
    dumps = list_nrd_dumps()
    total_domains = sum(d["domain_count"] for d in dumps)
    return {
        "total_domains": total_domains,
        "total_dumps": len(dumps),
        "latest_dump": dumps[-1]["filename"] if dumps else None,
    }