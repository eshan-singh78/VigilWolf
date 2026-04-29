"""VigilWolf v2 — NRD (Newly Registered Domains) API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from services.nrd_service import list_nrd_dumps, search_nrd_dumps, get_nrd_stats

router = APIRouter()


@router.get("/nrd/latest")
def nrd_latest():
    """List recent NRD dump files with metadata."""
    dumps = list_nrd_dumps()
    return {"dumps": dumps, "total": len(dumps)}


@router.get("/nrd/search")
def nrd_search(
    q: str = Query(..., min_length=1, description="Search query string"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results to return"),
):
    """Search across NRD dump files for matching domains."""
    results = search_nrd_dumps(query=q, limit=limit)
    return {"results": results, "total": len(results), "query": q}


@router.get("/nrd/stats")
def nrd_stats():
    """Get NRD statistics (total domains, dump count, latest dump)."""
    return get_nrd_stats()