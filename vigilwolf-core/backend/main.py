from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
import subprocess
import os
import logging
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from pathlib import Path

import config

from plugins.file_utils import get_latest_nrd_domains
from plugins.brand_search import brand_search as run_brand_search
from plugins.log_utils import clean_log
from plugins.whois_query import get_whois_info
from fastapi import Query

from scheduler import get_scheduler

from plugins.monitoring_service import get_monitoring_service

from plugins.storage_manager import get_storage_manager

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=config.LOG_FILE if config.LOG_FILE else None
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VigilWolf Domain Monitoring API",
    description="API for monitoring domain changes and capturing snapshots",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    """Initialize and start the monitoring system on application startup.
    
    Startup sequence:
    1. Ensure required directories exist
    2. Load existing state (groups and domains)
    3. Start the background scheduler
    4. Schedule checks for all active domains
    """
    logger.info("Starting Domain Monitoring System...")
    
    try:
        config.ensure_directories()
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

@app.on_event("shutdown")
async def shutdown_event():
    """Stop the monitoring system gracefully on application shutdown.
    
    Shutdown sequence:
    1. Stop accepting new requests (handled by FastAPI)
    2. Stop the background scheduler (waits for running jobs)
    3. Save any pending state
    4. Close resources
    """
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get('/whois')
async def whois_query(domain: str = Query(...)):
    result = get_whois_info(domain)
    return result

@app.get("/health")
async def health_check():
    """Health check endpoint that verifies system status.
    
    Returns:
        Status information including scheduler state and system readiness
    """
    try:
        scheduler = get_scheduler()
        scheduler_running = scheduler.scheduler is not None and scheduler.scheduler.running
        
        storage = get_storage_manager()
        groups = storage.load_groups()
        domains = storage.load_domains()
        active_domains = sum(1 for d in domains if d.active)
        
        return {
            "status": "ok",
            "scheduler_running": scheduler_running,
            "groups_count": len(groups),
            "domains_count": len(domains),
            "active_domains_count": active_domains,
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

@app.get('/nrd-latest')
async def nrd_latest(limit: int | None = Query(None), offset: int = Query(0)):
    filename, domains, total = get_latest_nrd_domains(limit=limit, offset=offset)
    return {"filename": filename, "domains": domains, "total": total}

@app.post('/brand-search')
async def brand_search(payload: dict, limit: int = Query(100), offset: int = Query(0)):
    from plugins.file_utils import find_latest_nrd_file

    brand = payload.get('brand') if isinstance(payload, dict) else None
    if not brand or not isinstance(brand, str):
        return {"results": [], "total": 0}

    filepath = find_latest_nrd_file()
    if not filepath:
        return {"results": [], "total": 0}

    data = run_brand_search(brand, filepath, limit=limit, offset=offset)
    return {"results": data.get("results", []), "total": data.get("total", 0)}

@app.get("/dump-nrd")
async def dump_nrd():
    """Download and process NRD (Newly Registered Domains) data.
    
    This endpoint runs the NRD download script which attempts to fetch domain data
    for the past 7 days. If some days fail to download (corrupted files, unavailable data),
    the script will skip those days and continue with available data.
    
    Returns:
        Status and output/error information from the download process
    """
    try:
        logger.info("Starting NRD download process...")
        result = subprocess.run(
            ["bash", "./nrd-fix-portable.sh"],
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )

        cleaned_stdout = clean_log(result.stdout)
        cleaned_stderr = clean_log(result.stderr)
        
        # Check if we got any domains even if there were some failures
        from plugins.file_utils import find_latest_nrd_file
        latest_file = find_latest_nrd_file()
        
        if latest_file and os.path.exists(latest_file):
            # Count domains (excluding comments and empty lines)
            try:
                with open(latest_file, 'r', encoding='utf-8', errors='ignore') as f:
                    domain_count = sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
                
                if domain_count > 0:
                    logger.info(f"NRD download completed with {domain_count} domains")
                    return {
                        "status": "Download Successful",
                        "output": cleaned_stdout,
                        "domain_count": domain_count,
                        "file": os.path.basename(latest_file),
                        "warnings": cleaned_stderr if cleaned_stderr else None
                    }
            except Exception as e:
                logger.warning(f"Error counting domains: {e}")
        
        # If we get here, either no file was created or it's empty
        if result.returncode != 0:
            logger.error(f"NRD download failed with return code {result.returncode}")
            return {
                "status": "Download Failed",
                "error": cleaned_stderr or cleaned_stdout,
                "message": "All NRD sources failed or were unavailable. Please try again later."
            }
        else:
            logger.warning("NRD download completed but no domains were found")
            return {
                "status": "Download Completed with Warnings",
                "output": cleaned_stdout,
                "warnings": cleaned_stderr,
                "message": "Download completed but no valid domain data was found."
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
    url: str = Field(..., description="Domain URL (must start with http:// or https://)")
    dump_mode: str = Field(..., description="Dump mode: 'html_only' or 'html_and_assets'")
    frequency_seconds: int = Field(..., gt=0, description="Check frequency in seconds (must be positive)")

class CreateGroupRequest(BaseModel):
    """Request model for creating a monitoring group."""
    name: str = Field(..., min_length=1, description="Group name (cannot be empty)")
    domains: List[DomainConfigRequest] = Field(..., min_length=1, description="List of domain configurations")

@app.post("/monitoring/groups", status_code=status.HTTP_201_CREATED)
async def create_monitoring_group(request: CreateGroupRequest):
    """Create a new monitoring group with domains.
    
    This endpoint creates a group and immediately performs the first dump for all domains.
    
    Requirements: 1.1
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create group: {str(e)}"
        )

@app.get("/monitoring/groups")
async def list_monitoring_groups():
    """Get all monitoring groups.
    
    Returns a list of all groups with their names and domain counts.
    
    Requirements: 6.1
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve groups: {str(e)}"
        )

@app.get("/monitoring/groups/{group_id}")
async def get_monitoring_group(group_id: str):
    """Get details for a specific monitoring group.
    
    Returns group information including all domain IDs.
    
    Requirements: 6.1
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve group: {str(e)}"
        )

@app.get("/monitoring/groups/{group_id}/domains")
async def get_group_domains(group_id: str):
    """Get all domains in a specific group.
    
    Returns detailed information about each domain in the group.
    
    Requirements: 6.1
    """
    try:
        monitoring_service = get_monitoring_service()
        
        group = monitoring_service.get_group(group_id)
        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group not found: {group_id}"
            )
        
        domains = monitoring_service.get_domains_in_group(group_id)
        
        return {
            'group_id': group_id,
            'group_name': group.name,
            'domains': [
                {
                    'id': domain.id,
                    'url': domain.url,
                    'dump_mode': domain.dump_mode,
                    'frequency_seconds': domain.frequency_seconds,
                    'created_at': domain.created_at,
                    'last_checked_at': domain.last_checked_at,
                    'active': domain.active
                }
                for domain in domains
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve domains: {str(e)}"
        )

@app.post("/monitoring/domains/{domain_id}/force-dump", status_code=status.HTTP_201_CREATED)
async def force_dump_domain(domain_id: str):
    """Trigger a manual force dump for a domain.
    
    Creates an immediate snapshot regardless of the scheduled frequency.
    
    Requirements: 5.1
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger force dump: {str(e)}"
        )

@app.get("/monitoring/domains/{domain_id}/snapshots")
async def get_domain_snapshots(domain_id: str):
    """Get all snapshots for a specific domain.
    
    Returns snapshots in chronological order (oldest to newest).
    
    Requirements: 7.3
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve snapshots: {str(e)}"
        )

@app.get("/monitoring/snapshots/{snapshot_id}")
async def get_snapshot_details(snapshot_id: str):
    """Get detailed information about a specific snapshot.
    
    Returns snapshot content, domain metadata, and complete logs.
    
    Requirements: 7.4, 7.5, 7.6
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve snapshot details: {str(e)}"
        )

@app.get("/monitoring/snapshots/{snapshot_id}/screenshot")
async def get_snapshot_screenshot(snapshot_id: str):
    """Get the screenshot image for a specific snapshot.
    
    Returns the screenshot file if it exists.
    
    Requirements: 7.4
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve screenshot: {str(e)}"
        )

@app.post("/monitoring/reset", status_code=status.HTTP_200_OK)
async def reset_monitoring_environment():
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
