from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import logging
import time
import uuid
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from pathlib import Path

import config
from database import init_db

from plugins.file_utils import get_latest_nrd_domains
from plugins.brand_search import brand_search as run_brand_search
from plugins.whois_query import get_whois_info
from plugins.nrd_downloader import download_nrd_data, cleanup_temp_files

from scheduler import get_scheduler

from plugins.monitoring_service import get_monitoring_service

from plugins.storage_manager import get_storage_manager

from rate_limiter import check_rate_limit

# Prometheus metrics (optional)
if config.ENABLE_PROMETHEUS:
    try:
        from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
        REQUEST_COUNT = Counter('vigilwolf_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
        REQUEST_DURATION = Histogram('vigilwolf_request_duration_seconds', 'Request duration', ['method', 'endpoint'])
        METRICS_AVAILABLE = True
    except ImportError:
        METRICS_AVAILABLE = False
else:
    METRICS_AVAILABLE = False


class RequestIdFilter(logging.Filter):
    """Add request ID to log records."""
    def filter(self, record):
        record.request_id = getattr(record, 'request_id', 'none')
        return True


logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s',
    filename=config.LOG_FILE if config.LOG_FILE else None
)
logger = logging.getLogger(__name__)
logger.addFilter(RequestIdFilter())


security = HTTPBearer(auto_error=False)




# --- Authentication ---
def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify API key. In production, a key is always required."""
    # Production: must have API_KEY configured and provided
    if config.ENVIRONMENT == "production":
        if not config.API_KEY:
            logger.error("API_KEY not configured in production")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server misconfiguration: authentication not configured",
            )
        if not credentials or credentials.credentials != config.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials

    # Development: require key if configured, allow anonymous if not
    if not config.API_KEY:
        return "anonymous"

    if not credentials or credentials.credentials != config.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    logger.info("Starting Domain Monitoring System...")
    try:
        config.ensure_directories()
        init_db()
        logger.info(f"Monitoring data directory: {config.MONITORING_DATA_DIR}")

        storage = get_storage_manager()
        groups = storage.load_groups()
        domains = storage.load_domains()
        logger.info(f"Loaded {len(groups)} groups and {len(domains)} domains from storage")

        scheduler = get_scheduler()
        scheduler.start_scheduler()
        logger.info("Background scheduler started successfully")
        logger.info(f"Configuration: {config.get_config_summary()}")
        logger.info("Domain Monitoring System startup complete")
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}", exc_info=True)
        raise

    yield

    logger.info("Shutting down Domain Monitoring System...")
    try:
        scheduler = get_scheduler()
        scheduler.stop_scheduler()
        logger.info("Background scheduler stopped successfully")

        storage = get_storage_manager()
        groups = storage.load_groups()
        domains = storage.load_domains()
        logger.info(f"Final state: {len(groups)} groups, {len(domains)} domains")
        logger.info("Domain Monitoring System shutdown complete")
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}", exc_info=True)


app = FastAPI(
    title="VigilWolf Domain Monitoring API",
    description="API for monitoring domain changes and capturing snapshots",
    version="1.0.0",
    lifespan=lifespan
)


# --- Security Middleware ---
class SecurityHeadersMiddleware:
    """Add security headers to all responses."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"x-xss-protection", b"1; mode=block"))
                headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                headers.append((b"permissions-policy", b"geolocation=(), microphone=(), camera=()"))
                if config.ENVIRONMENT == "production":
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeadersMiddleware)

if config.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[h.strip() for h in config.TRUSTED_HOSTS if h.strip() and h.strip() != "*"]
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- Request logging middleware ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing and request ID."""
    request_id = request.headers.get(config.REQUEST_ID_HEADER, str(uuid.uuid4())[:8])
    request.state.request_id = request_id

    start_time = time.time()
    path = request.url.path
    method = request.method

    try:
        response = await call_next(request)
        duration = time.time() - start_time
        status_code = response.status_code

        if METRICS_AVAILABLE:
            REQUEST_COUNT.labels(method=method, endpoint=path, status=str(status_code)).inc()
            REQUEST_DURATION.labels(method=method, endpoint=path).observe(duration)

        logger.info(
            f"{method} {path} {status_code} - {duration:.3f}s",
            extra={"request_id": request_id}
        )
        return response
    except Exception as e:
        logger.error(f"Unhandled exception in {method} {path}: {e}", exc_info=True, extra={"request_id": request_id})
        raise


# --- HTTPS redirect (production only) ---
@app.middleware("http")
async def https_redirect(request: Request, call_next):
    """Redirect HTTP to HTTPS in production."""
    if config.ENVIRONMENT == "production" and config.FORCE_HTTPS:
        if request.headers.get("x-forwarded-proto", "https") == "http":
            url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(url), status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return await call_next(request)


# --- Prometheus metrics endpoint ---
if METRICS_AVAILABLE:
    @app.get("/metrics", dependencies=[Depends(verify_api_key)])
    async def metrics():
        """Prometheus metrics endpoint."""
        from fastapi.responses import Response
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# --- Endpoints ---

@app.get('/whois', responses={
    200: {"description": "WHOIS data for domain"},
    401: {"description": "Unauthorized"},
    429: {"description": "Rate limit exceeded"}
})
async def whois_query(
    domain: str = Query(..., min_length=1, max_length=253, examples=["example.com"]),
    request: Request = None,
    api_key: str = Depends(verify_api_key)
):
    client_ip = request.client.host if request.client else "unknown"
    allowed, remaining = check_rate_limit(client_ip, "/whois")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"X-RateLimit-Remaining": str(remaining)}
        )

    result = get_whois_info(domain)
    return result


@app.get("/health", responses={
    200: {
        "description": "System health status",
        "content": {
            "application/json": {
                "example": {
                    "status": "ok",
                    "scheduler_running": True,
                    "groups_count": 5,
                    "domains_count": 12,
                    "active_domains_count": 10,
                    "database_healthy": True
                }
            }
        }
    }
})
async def health_check():
    """Health check endpoint that verifies system status."""
    try:
        scheduler = get_scheduler()
        scheduler_running = scheduler.scheduler is not None and scheduler.scheduler.running

        storage = get_storage_manager()
        groups = storage.load_groups()
        domains = storage.load_domains()
        active_domains = sum(1 for d in domains if d.active)

        db_healthy = True
        try:
            # Quick DB health check
            from database import get_session
            from sqlalchemy import text
            with get_session() as session:
                session.execute(text("SELECT 1"))
                session.commit()
        except Exception:
            db_healthy = False

        status_code = "ok" if db_healthy else "degraded"

        return {
            "status": status_code,
            "scheduler_running": scheduler_running,
            "groups_count": len(groups),
            "domains_count": len(domains),
            "active_domains_count": active_domains,
            "database_healthy": db_healthy,
            "config": {
                "monitoring_data_dir": config.MONITORING_DATA_DIR,
                "screenshot_enabled": config.SCREENSHOT_ENABLED,
                "max_concurrent_checks": config.MAX_CONCURRENT_CHECKS
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


@app.get("/config")
async def get_config(api_key: str = Depends(verify_api_key)):
    """Get current system configuration (safe values only)."""
    return {
        "environment": config.ENVIRONMENT,
        "monitoring": {
            "data_dir": config.MONITORING_DATA_DIR,
            "screenshot_enabled": config.SCREENSHOT_ENABLED,
            "screenshot_width": config.SCREENSHOT_WIDTH,
            "screenshot_height": config.SCREENSHOT_HEIGHT,
            "max_concurrent_checks": config.MAX_CONCURRENT_CHECKS,
            "default_timeout_seconds": config.DEFAULT_TIMEOUT_SECONDS,
            "max_domains_per_group": config.MAX_DOMAINS_PER_GROUP,
            "snapshot_retention_days": config.SNAPSHOT_RETENTION_DAYS,
            "min_check_frequency_seconds": config.MIN_CHECK_FREQUENCY_SECONDS,
            "alert_threshold": config.ALERT_THRESHOLD,
        },
        "security": {
            "api_key_configured": bool(config.API_KEY),
            "rate_limit_per_minute": config.RATE_LIMIT_PER_MINUTE,
            "force_https": config.FORCE_HTTPS,
            "trusted_hosts": config.TRUSTED_HOSTS,
        },
        "scheduler": {
            "timezone": config.SCHEDULER_TIMEZONE,
            "max_instances": config.SCHEDULER_MAX_INSTANCES,
            "coalesce": config.SCHEDULER_COALESCE,
        },
        "features": {
            "prometheus_enabled": config.ENABLE_PROMETHEUS and METRICS_AVAILABLE,
            "redis_available": bool(config.REDIS_URL),
        }
    }


@app.get('/nrd-latest')
async def nrd_latest(
    limit: int | None = Query(None, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    api_key: str = Depends(verify_api_key)
):
    filename, domains, total = get_latest_nrd_domains(limit=limit, offset=offset)
    return {"filename": filename, "domains": domains, "total": total}


class BrandSearchRequest(BaseModel):
    brand: str = Field(..., min_length=1, max_length=200)


@app.post('/brand-search')
async def brand_search(
    payload: BrandSearchRequest,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    api_key: str = Depends(verify_api_key)
):
    from plugins.file_utils import find_latest_nrd_file

    filepath = find_latest_nrd_file()
    if not filepath:
        return {"results": [], "total": 0}

    data = run_brand_search(payload.brand, filepath, limit=limit, offset=offset)
    return {"results": data.get("results", []), "total": data.get("total", 0)}


@app.get("/dump-nrd")
async def dump_nrd(api_key: str = Depends(verify_api_key)):
    """Download and process NRD (Newly Registered Domains) data."""
    try:
        logger.info("Starting NRD download process...")

        result = download_nrd_data(
            day_range=7,
            retries=config.MAX_RETRIES,
            timeout=config.DEFAULT_TIMEOUT_SECONDS
        )

        if result["success"]:
            logger.info(
                f"NRD download completed: {result['total_domains']} domains "
                f"from {result['days_downloaded']} days"
            )
            return {
                "status": "Download Successful",
                "domain_count": result["total_domains"],
                "file": result["timestamped_file"].name if result["timestamped_file"] else None,
                "merged_file": result["merged_file"].name,
                "days_downloaded": result["days_downloaded"],
                "days_failed": result["days_failed"],
                "warnings": result["errors"] if result["errors"] else None
            }

        logger.error("NRD download failed: no domains retrieved")
        return {
            "status": "Download Failed",
            "error": "; ".join(result["errors"]) if result["errors"] else "Unknown error",
            "message": "All NRD sources failed or were unavailable. Please try again later."
        }

    except Exception as e:
        logger.error(f"Unexpected error during NRD download: {str(e)}", exc_info=True)
        return {
            "status": "Download Failed",
            "error": str(e),
            "message": "An unexpected error occurred during the download process."
        }


class DomainConfigRequest(BaseModel):
    """Request model for domain configuration."""
    url: str = Field(..., min_length=1, max_length=2048, description="Domain URL (must start with http:// or https://)")
    dump_mode: str = Field(..., pattern="^(html_only|html_and_assets)$")
    frequency_seconds: int = Field(..., gt=0, description="Check frequency in seconds (must be positive)")


class CreateGroupRequest(BaseModel):
    """Request model for creating a monitoring group."""
    name: str = Field(..., min_length=1, max_length=200, description="Group name (cannot be empty)")
    domains: List[DomainConfigRequest] = Field(..., min_length=1, description="List of domain configurations")


@app.post("/monitoring/groups", status_code=status.HTTP_201_CREATED)
async def create_monitoring_group(request: CreateGroupRequest, api_key: str = Depends(verify_api_key)):
    """Create a new monitoring group with domains."""
    try:
        monitoring_service = get_monitoring_service()

        domain_configs = [
            {
                'url': domain.url,
                'dump_mode': domain.dump_mode,
                'frequency_seconds': domain.frequency_seconds
            }
            for domain in request.domains
        ]

        group, domains = monitoring_service.create_group(request.name, domain_configs)

        return {
            'id': group.id,
            'name': group.name,
            'created_at': group.created_at,
            'domain_count': len(domains),
            'domains': [
                {
                    'id': domain.id,
                    'url': domain.url,
                    'dump_mode': domain.dump_mode,
                    'frequency_seconds': domain.frequency_seconds
                }
                for domain in domains
            ]
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create group: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create group: {str(e)}"
        )


@app.get("/monitoring/groups")
async def list_monitoring_groups(api_key: str = Depends(verify_api_key)):
    """Get all monitoring groups."""
    try:
        monitoring_service = get_monitoring_service()
        groups = monitoring_service.get_all_groups()

        return {
            'groups': [
                {
                    'id': group.id,
                    'name': group.name,
                    'created_at': group.created_at,
                    'domain_count': len(group.domain_ids)
                }
                for group in groups
            ]
        }
    except Exception as e:
        logger.error(f"Failed to retrieve groups: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve groups: {str(e)}"
        )


@app.get("/monitoring/groups/{group_id}")
async def get_monitoring_group(group_id: str, api_key: str = Depends(verify_api_key)):
    """Get details for a specific monitoring group."""
    try:
        monitoring_service = get_monitoring_service()
        group = monitoring_service.get_group(group_id)

        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group not found: {group_id}"
            )

        return {
            'id': group.id,
            'name': group.name,
            'created_at': group.created_at,
            'domain_ids': group.domain_ids,
            'domain_count': len(group.domain_ids)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve group: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve group: {str(e)}"
        )


@app.get("/monitoring/groups/{group_id}/domains")
async def get_group_domains(group_id: str, api_key: str = Depends(verify_api_key)):
    """Get all domains in a specific group."""
    try:
        monitoring_service = get_monitoring_service()

        group = monitoring_service.get_group(group_id)
        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group not found: {group_id}"
            )

        domains = monitoring_service.get_domains_in_group(group_id)

        domain_list = []
        for domain in domains:
            latest_ping = monitoring_service.get_latest_ping_log(domain.id)
            domain_list.append({
                'id': domain.id,
                'url': domain.url,
                'dump_mode': domain.dump_mode,
                'frequency_seconds': domain.frequency_seconds,
                'created_at': domain.created_at,
                'last_checked_at': domain.last_checked_at,
                'active': domain.active,
                'change_detected': latest_ping['change_detected'] if latest_ping else False
            })

        return {
            'group_id': group_id,
            'group_name': group.name,
            'domains': domain_list
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve domains: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve domains: {str(e)}"
        )


@app.post("/monitoring/domains/{domain_id}/force-dump", status_code=status.HTTP_201_CREATED)
async def force_dump_domain(domain_id: str, api_key: str = Depends(verify_api_key)):
    """Trigger a manual force dump for a domain."""
    try:
        monitoring_service = get_monitoring_service()

        snapshot = monitoring_service.trigger_force_dump(domain_id)

        return {
            'snapshot_id': snapshot.id,
            'domain_id': snapshot.domain_id,
            'timestamp': snapshot.timestamp,
            'trigger_type': snapshot.trigger_type,
            'success': snapshot.success,
            'error_message': snapshot.error_message
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to trigger force dump: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger force dump: {str(e)}"
        )


@app.get("/monitoring/domains/{domain_id}/snapshots")
async def get_domain_snapshots(domain_id: str, api_key: str = Depends(verify_api_key)):
    """Get all snapshots for a specific domain."""
    try:
        monitoring_service = get_monitoring_service()

        domain = monitoring_service.get_domain(domain_id)
        if domain is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Domain not found: {domain_id}"
            )

        snapshots = monitoring_service.get_snapshots_for_domain(domain_id)

        return {
            'domain_id': domain_id,
            'domain_url': domain.url,
            'snapshots': [
                {
                    'id': snapshot.id,
                    'timestamp': snapshot.timestamp,
                    'trigger_type': snapshot.trigger_type,
                    'success': snapshot.success,
                    'asset_count': snapshot.asset_count,
                    'has_screenshot': snapshot.screenshot_path is not None,
                    'error_message': snapshot.error_message
                }
                for snapshot in snapshots
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve snapshots: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve snapshots: {str(e)}"
        )


@app.get("/monitoring/snapshots/{snapshot_id}")
async def get_snapshot_details(snapshot_id: str, api_key: str = Depends(verify_api_key)):
    """Get detailed information about a specific snapshot."""
    try:
        monitoring_service = get_monitoring_service()

        details = monitoring_service.get_snapshot_details(snapshot_id)

        if details is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Snapshot not found: {snapshot_id}"
            )

        snapshot = details['snapshot']
        domain = details['domain']

        return {
            'snapshot': {
                'id': snapshot.id,
                'timestamp': snapshot.timestamp,
                'trigger_type': snapshot.trigger_type,
                'success': snapshot.success,
                'error_message': snapshot.error_message,
                'html_path': snapshot.html_path,
                'screenshot_path': snapshot.screenshot_path,
                'assets_dir': snapshot.assets_dir,
                'asset_count': snapshot.asset_count
            },
            'domain': {
                'id': domain.id,
                'url': domain.url,
                'dump_mode': domain.dump_mode,
                'frequency_seconds': domain.frequency_seconds,
                'last_checked_at': domain.last_checked_at
            },
            'html_content': details['html_content'],
            'screenshot_exists': details['screenshot_exists'],
            'assets': details['assets'],
            'ping_logs': [
                {
                    'timestamp': log.timestamp,
                    'reachable': log.reachable,
                    'status_code': log.status_code,
                    'change_detected': log.change_detected,
                    'message': log.message
                }
                for log in details['ping_logs']
            ],
            'dump_logs': [
                {
                    'timestamp': log.timestamp,
                    'trigger_type': log.trigger_type,
                    'snapshot_id': log.snapshot_id,
                    'success': log.success,
                    'error_message': log.error_message,
                    'message': log.message
                }
                for log in details['dump_logs']
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve snapshot details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve snapshot details: {str(e)}"
        )


@app.get("/monitoring/snapshots/{snapshot_id}/screenshot")
async def get_snapshot_screenshot(snapshot_id: str, api_key: str = Depends(verify_api_key)):
    """Get the screenshot image for a specific snapshot."""
    try:
        monitoring_service = get_monitoring_service()

        details = monitoring_service.get_snapshot_details(snapshot_id)

        if details is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Snapshot not found: {snapshot_id}"
            )

        snapshot = details['snapshot']

        if not snapshot.screenshot_path or not details['screenshot_exists']:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Screenshot not available for snapshot: {snapshot_id}"
            )

        storage = get_storage_manager()
        screenshot_path = storage.data_dir / snapshot.screenshot_path

        if not screenshot_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Screenshot file not found: {screenshot_path}"
            )

        return FileResponse(
            path=str(screenshot_path),
            media_type="image/png",
            filename=f"snapshot_{snapshot_id}.png"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve screenshot: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve screenshot: {str(e)}"
        )


@app.post("/monitoring/reset", status_code=status.HTTP_200_OK)
async def reset_monitoring_environment(api_key: str = Depends(verify_api_key)):
    """Reset the monitoring environment by deleting all data.

    This will delete:
    - All monitoring groups
    - All monitored domains
    - All snapshots and logs

    WARNING: This action cannot be undone!
    """
    try:
        storage = get_storage_manager()

        scheduler = get_scheduler()
        was_running = scheduler.scheduler is not None and scheduler.scheduler.running
        if was_running:
            scheduler.stop_scheduler()

        stats = storage.reset_environment()

        if was_running:
            scheduler.start_scheduler()

        logger.info(f"Environment reset: {stats}")

        return {
            'success': True,
            'message': 'Monitoring environment has been reset',
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Failed to reset environment: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset environment: {str(e)}"
        )
