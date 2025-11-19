"""Monitoring service for the Domain Monitoring System.

Provides core business logic for:
- Group creation and management
- Domain configuration
- Snapshot orchestration
- Force dump triggering
"""
from typing import List, Optional, Dict, Tuple
from models import Group, Domain, Snapshot, PingLogEntry, DumpLogEntry
from plugins.storage_manager import get_storage_manager
from plugins.capture_engine import get_capture_engine
from config import MAX_DOMAINS_PER_GROUP

class MonitoringService:
    """Core monitoring service for managing groups and domains."""
    
    def __init__(self):
        """Initialize monitoring service."""
        self.storage = get_storage_manager()
        self.capture = get_capture_engine()
    
    def create_group(
        self,
        name: str,
        domain_configs: List[Dict[str, any]]
    ) -> Tuple[Group, List[Domain]]:
        """Create a new monitoring group with domains.
        
        Args:
            name: Name of the group
            domain_configs: List of domain configuration dictionaries, each containing:
                - url: Domain URL
                - dump_mode: "html_only" or "html_and_assets"
                - frequency_seconds: Check frequency in seconds
        
        Returns:
            Tuple of (created Group, list of created Domains)
            
        Raises:
            ValueError: If validation fails
        """
        if not name or not name.strip():
            raise ValueError("Group name cannot be empty")
        
        if not domain_configs:
            raise ValueError("At least one domain is required")
        
        if len(domain_configs) > MAX_DOMAINS_PER_GROUP:
            raise ValueError(f"Cannot create group with more than {MAX_DOMAINS_PER_GROUP} domains")
        
        for config in domain_configs:
            self._validate_domain_config(config)
        
        group = Group.create(name=name.strip())
        
        domains = []
        for config in domain_configs:
            domain = Domain.create(
                group_id=group.id,
                url=config['url'],
                dump_mode=config['dump_mode'],
                frequency_seconds=config['frequency_seconds']
            )
            domains.append(domain)
            group.domain_ids.append(domain.id)
        
        self.storage.save_group(group)
        for domain in domains:
            self.storage.save_domain(domain)
        
        for domain in domains:
            self.perform_first_dump(domain)
        
        from scheduler import get_scheduler
        scheduler = get_scheduler()
        for domain in domains:
            scheduler.schedule_domain_check(domain)
        
        return group, domains
    
    def get_all_groups(self) -> List[Group]:
        """Get all monitoring groups.
        
        Returns:
            List of all Group objects
        """
        return self.storage.load_groups()
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get a specific group by ID.
        
        Args:
            group_id: ID of the group to retrieve
            
        Returns:
            Group object or None if not found
        """
        return self.storage.get_group(group_id)
    
    def get_domains_in_group(self, group_id: str) -> List[Domain]:
        """Get all domains in a specific group.
        
        Args:
            group_id: ID of the group
            
        Returns:
            List of Domain objects in the group
        """
        return self.storage.get_domains_by_group(group_id)
    
    def get_domain(self, domain_id: str) -> Optional[Domain]:
        """Get a specific domain by ID.
        
        Args:
            domain_id: ID of the domain to retrieve
            
        Returns:
            Domain object or None if not found
        """
        return self.storage.get_domain(domain_id)
    
    def perform_first_dump(self, domain: Domain) -> Snapshot:
        """Perform the first dump for a newly created domain.
        
        Args:
            domain: Domain to dump
            
        Returns:
            Created Snapshot object
        """
        snapshot = self._perform_dump(domain, trigger_type="initial")
        
        from datetime import datetime
        domain.last_checked_at = datetime.utcnow().isoformat() + 'Z'
        self.storage.save_domain(domain)
        
        return snapshot
    
    def trigger_force_dump(self, domain_id: str) -> Snapshot:
        """Trigger a manual force dump for a domain.
        
        Args:
            domain_id: ID of the domain to dump
            
        Returns:
            Created Snapshot object
            
        Raises:
            ValueError: If domain not found or concurrent dump in progress
        """
        domain = self.get_domain(domain_id)
        if domain is None:
            raise ValueError(f"Domain not found: {domain_id}")
        
        import os
        from pathlib import Path
        
        lock_file = Path(self.storage.data_dir) / "snapshots" / domain_id / ".dump_lock"
        
        if lock_file.exists():
            raise ValueError(f"A dump is already in progress for domain {domain_id}")
        
        try:
            lock_file.parent.mkdir(parents=True, exist_ok=True)
            lock_file.touch()
            
            snapshot = self._perform_dump(domain, trigger_type="manual")
            
            return snapshot
        finally:
            if lock_file.exists():
                lock_file.unlink()
    
    def _perform_dump(
        self,
        domain: Domain,
        trigger_type: str
    ) -> Snapshot:
        """Perform a dump for a domain with comprehensive error handling.
        
        This method implements graceful degradation:
        - If HTML fetch fails, the dump fails but domain continues monitoring
        - If screenshot fails, dump continues without screenshot
        - If asset downloads fail, dump continues with partial assets
        
        Args:
            domain: Domain to dump
            trigger_type: Type of dump trigger ("initial", "automatic", "manual")
            
        Returns:
            Created Snapshot object
        """
        from datetime import datetime
        from pathlib import Path
        
        try:
            html_content, fetch_success = self.capture.fetch_html(domain.url)
            
            if fetch_success:
                ping_entry = PingLogEntry.create(
                    reachable=True,
                    status_code=200,
                    change_detected=False,
                    message=f"{trigger_type.capitalize()} dump for domain {domain.url}"
                )
            else:
                ping_entry = PingLogEntry.create(
                    reachable=False,
                    status_code=None,
                    change_detected=False,
                    message=f"Failed to fetch HTML for domain {domain.url} after retries"
                )
            
            self.storage.append_ping_log(domain.id, ping_entry)
            
            if not fetch_success:
                snapshot = Snapshot.create(
                    domain_id=domain.id,
                    trigger_type=trigger_type,
                    html_path="",
                    screenshot_path=None,
                    assets_dir=None,
                    asset_count=0,
                    success=False,
                    error_message="Failed to fetch HTML after retries"
                )
                
                dump_entry = DumpLogEntry.create(
                    trigger_type=trigger_type,
                    snapshot_id=snapshot.id,
                    success=False,
                    message=f"Failed to create {trigger_type} dump",
                    error_message="Failed to fetch HTML after retries"
                )
                self.storage.append_dump_log(domain.id, dump_entry)
                
                return snapshot
            
            timestamp = datetime.utcnow().isoformat() + 'Z'
            
            snapshot_dir = self.storage.create_snapshot_directory(domain.id, timestamp)
            
            html_path = self.storage.save_html(snapshot_dir, html_content)
            
            import logging
            logger = logging.getLogger(__name__)
            
            screenshot_path = None
            screenshot_file = f"{snapshot_dir}/screenshot.png"
            
            logger.info(f"Attempting to capture screenshot for {domain.url}")
            screenshot_success = self.capture.capture_screenshot(domain.url, screenshot_file)
            
            if screenshot_success:
                screenshot_path = str(Path(snapshot_dir).relative_to(self.storage.data_dir) / "screenshot.png")
                logger.info(f"✓ Screenshot captured successfully: {screenshot_path}")
            else:
                logger.warning(f"✗ Screenshot capture failed for {domain.url}, continuing without screenshot")
            
            assets_dir = None
            asset_count = 0
            
            if domain.dump_mode == "html_and_assets":
                try:
                    downloaded_assets = self.capture.download_assets(
                        html_content,
                        domain.url,
                        snapshot_dir
                    )
                    asset_count = len(downloaded_assets)
                    
                    if asset_count > 0:
                        assets_dir = str(Path(snapshot_dir).relative_to(self.storage.data_dir) / "assets")
                except Exception as e:
                    asset_count = 0
                    assets_dir = None
            
            snapshot = Snapshot(
                id=str(__import__('uuid').uuid4()),
                domain_id=domain.id,
                timestamp=timestamp,
                trigger_type=trigger_type,
                html_path=html_path,
                screenshot_path=screenshot_path,
                assets_dir=assets_dir,
                asset_count=asset_count,
                success=True,
                error_message=None
            )
            
            self.storage.save_snapshot_metadata(snapshot)
            
            dump_entry = DumpLogEntry.create(
                trigger_type=trigger_type,
                snapshot_id=snapshot.id,
                success=True,
                message=f"Successfully created {trigger_type} dump"
            )
            self.storage.append_dump_log(domain.id, dump_entry)
            
            return snapshot
        except Exception as e:
            snapshot = Snapshot.create(
                domain_id=domain.id,
                trigger_type=trigger_type,
                html_path="",
                screenshot_path=None,
                assets_dir=None,
                asset_count=0,
                success=False,
                error_message=f"Unexpected error during dump: {str(e)}"
            )
            
            dump_entry = DumpLogEntry.create(
                trigger_type=trigger_type,
                snapshot_id=snapshot.id,
                success=False,
                message=f"Failed to create {trigger_type} dump",
                error_message=f"Unexpected error: {str(e)}"
            )
            self.storage.append_dump_log(domain.id, dump_entry)
            
            return snapshot
    
    def get_snapshots_for_domain(self, domain_id: str) -> List[Snapshot]:
        """Get all snapshots for a specific domain in chronological order.
        
        Args:
            domain_id: ID of the domain
            
        Returns:
            List of Snapshot objects ordered by timestamp (oldest to newest)
        """
        return self.storage.load_snapshots_for_domain(domain_id)
    
    def get_snapshot_details(self, snapshot_id: str) -> Optional[Dict]:
        """Get detailed information about a specific snapshot.
        
        Args:
            snapshot_id: ID of the snapshot
            
        Returns:
            Dictionary containing:
                - snapshot: Snapshot object
                - domain: Domain object with metadata
                - ping_logs: List of PingLogEntry objects
                - dump_logs: List of DumpLogEntry objects
                - html_content: HTML content (if available)
                - screenshot_exists: Boolean indicating if screenshot file exists
                - assets: List of asset filenames (if assets were captured)
                - is_valid: Boolean indicating if snapshot integrity is valid
                - validation_errors: List of validation error messages
            Returns None if snapshot not found
        """
        snapshot = self.storage.get_snapshot(snapshot_id)
        if snapshot is None:
            return None
        
        is_valid, validation_errors = self.storage.validate_snapshot(snapshot)
        
        domain = self.get_domain(snapshot.domain_id)
        if domain is None:
            return None
        
        ping_logs = self.storage.read_ping_log(snapshot.domain_id)
        dump_logs = self.storage.read_dump_log(snapshot.domain_id)
        
        html_content = None
        if snapshot.html_path:
            try:
                html_content = self.storage.load_html(snapshot.html_path)
            except Exception:
                html_content = None
        
        screenshot_exists = False
        if snapshot.screenshot_path:
            screenshot_file = self.storage.data_dir / snapshot.screenshot_path
            screenshot_exists = screenshot_file.exists()
        
        assets = []
        if snapshot.assets_dir:
            assets_path = self.storage.data_dir / snapshot.assets_dir
            if assets_path.exists() and assets_path.is_dir():
                assets = [f.name for f in assets_path.iterdir() if f.is_file()]
                assets.sort()  # Sort alphabetically
        
        return {
            'snapshot': snapshot,
            'domain': domain,
            'ping_logs': ping_logs,
            'dump_logs': dump_logs,
            'html_content': html_content,
            'screenshot_exists': screenshot_exists,
            'assets': assets,
            'is_valid': is_valid,
            'validation_errors': validation_errors
        }
    
    def validate_all_snapshots(self, domain_id: Optional[str] = None) -> Dict[str, tuple[bool, list[str]]]:
        """Validate integrity of all snapshots for a domain or all domains.
        
        Args:
            domain_id: Optional domain ID to validate snapshots for.
                      If None, validates all snapshots.
        
        Returns:
            Dictionary mapping snapshot IDs to (is_valid, errors) tuples
        """
        results = {}
        
        if domain_id:
            snapshots = self.storage.load_snapshots_for_domain(domain_id)
            for snapshot in snapshots:
                is_valid, errors = self.storage.validate_snapshot(snapshot)
                results[snapshot.id] = (is_valid, errors)
        else:
            domains = self.storage.load_domains()
            for domain in domains:
                snapshots = self.storage.load_snapshots_for_domain(domain.id)
                for snapshot in snapshots:
                    is_valid, errors = self.storage.validate_snapshot(snapshot)
                    results[snapshot.id] = (is_valid, errors)
        
        return results
    
    def _validate_domain_config(self, config: Dict[str, any]) -> None:
        """Validate a domain configuration.
        
        Args:
            config: Domain configuration dictionary
            
        Raises:
            ValueError: If validation fails
        """
        required_fields = ['url', 'dump_mode', 'frequency_seconds']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
        
        url = config['url']
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        
        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        dump_mode = config['dump_mode']
        if dump_mode not in ['html_only', 'html_and_assets']:
            raise ValueError("dump_mode must be 'html_only' or 'html_and_assets'")
        
        frequency = config['frequency_seconds']
        if not isinstance(frequency, int) or frequency <= 0:
            raise ValueError("frequency_seconds must be a positive integer")

_monitoring_service = None

def get_monitoring_service() -> MonitoringService:
    """Get the global monitoring service instance.
    
    Returns:
        MonitoringService instance
    """
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = MonitoringService()
    return _monitoring_service
