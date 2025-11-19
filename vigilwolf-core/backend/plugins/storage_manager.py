"""Storage manager for the Domain Monitoring System.

Handles all file system operations including:
- Group and domain metadata persistence
- Snapshot directory creation and management
- Log file operations (ping and dump logs)
- HTML content storage and retrieval
"""
import os
import json
import fcntl
from typing import List, Optional
from pathlib import Path
from models import Group, Domain, Snapshot, PingLogEntry, DumpLogEntry
from config import MONITORING_DATA_DIR

class StorageManager:
    """Manages all file system operations for the monitoring system."""
    
    def __init__(self, data_dir: str = MONITORING_DATA_DIR):
        """Initialize storage manager with data directory."""
        self.data_dir = Path(data_dir)
        self.groups_file = self.data_dir / "groups.json"
        self.domains_file = self.data_dir / "domains.json"
        self.snapshots_dir = self.data_dir / "snapshots"
        
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
    
    def save_group(self, group: Group) -> None:
        """Save a single group to the groups file.
        
        Args:
            group: Group object to save
        """
        groups = self.load_groups()
        
        existing_index = None
        for i, g in enumerate(groups):
            if g.id == group.id:
                existing_index = i
                break
        
        if existing_index is not None:
            groups[existing_index] = group
        else:
            groups.append(group)
        
        self._write_json_file(self.groups_file, [g.to_dict() for g in groups])
    
    def load_groups(self) -> List[Group]:
        """Load all groups from the groups file.
        
        Returns:
            List of Group objects
        """
        if not self.groups_file.exists():
            return []
        
        data = self._read_json_file(self.groups_file)
        return [Group.from_dict(g) for g in data]
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get a specific group by ID.
        
        Args:
            group_id: ID of the group to retrieve
            
        Returns:
            Group object or None if not found
        """
        groups = self.load_groups()
        for group in groups:
            if group.id == group_id:
                return group
        return None
    
    def save_domain(self, domain: Domain) -> None:
        """Save a single domain to the domains file.
        
        Args:
            domain: Domain object to save
        """
        domains = self.load_domains()
        
        existing_index = None
        for i, d in enumerate(domains):
            if d.id == domain.id:
                existing_index = i
                break
        
        if existing_index is not None:
            domains[existing_index] = domain
        else:
            domains.append(domain)
        
        self._write_json_file(self.domains_file, [d.to_dict() for d in domains])
    
    def load_domains(self) -> List[Domain]:
        """Load all domains from the domains file.
        
        Returns:
            List of Domain objects
        """
        if not self.domains_file.exists():
            return []
        
        data = self._read_json_file(self.domains_file)
        return [Domain.from_dict(d) for d in data]
    
    def get_domain(self, domain_id: str) -> Optional[Domain]:
        """Get a specific domain by ID.
        
        Args:
            domain_id: ID of the domain to retrieve
            
        Returns:
            Domain object or None if not found
        """
        domains = self.load_domains()
        for domain in domains:
            if domain.id == domain_id:
                return domain
        return None
    
    def get_domains_by_group(self, group_id: str) -> List[Domain]:
        """Get all domains belonging to a specific group.
        
        Args:
            group_id: ID of the group
            
        Returns:
            List of Domain objects
        """
        domains = self.load_domains()
        return [d for d in domains if d.group_id == group_id]
    
    def create_snapshot_directory(self, domain_id: str, timestamp: str) -> str:
        """Create a directory for a new snapshot.
        
        Args:
            domain_id: ID of the domain
            timestamp: ISO timestamp for the snapshot
            
        Returns:
            Absolute path to the created snapshot directory
        """
        domain_dir = self.snapshots_dir / domain_id
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        clean_timestamp = timestamp.replace(':', '-').replace('.', '-')
        snapshot_dir = domain_dir / clean_timestamp
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        return str(snapshot_dir)
    
    def save_snapshot_metadata(self, snapshot: Snapshot) -> None:
        """Save snapshot metadata to a JSON file.
        
        Args:
            snapshot: Snapshot object to save
        """
        html_path = Path(snapshot.html_path)
        snapshot_dir = self.data_dir / html_path.parent
        
        metadata_file = snapshot_dir / "metadata.json"
        self._write_json_file(metadata_file, snapshot.to_dict())
    
    def load_snapshots_for_domain(self, domain_id: str) -> List[Snapshot]:
        """Load all snapshots for a specific domain.
        
        Args:
            domain_id: ID of the domain
            
        Returns:
            List of Snapshot objects ordered by timestamp
        """
        domain_dir = self.snapshots_dir / domain_id
        if not domain_dir.exists():
            return []
        
        snapshots = []
        for snapshot_dir in domain_dir.iterdir():
            if snapshot_dir.is_dir():
                metadata_file = snapshot_dir / "metadata.json"
                if metadata_file.exists():
                    data = self._read_json_file(metadata_file)
                    snapshots.append(Snapshot.from_dict(data))
        
        snapshots.sort(key=lambda s: s.timestamp)
        return snapshots
    
    def get_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        """Get a specific snapshot by ID.
        
        Args:
            snapshot_id: ID of the snapshot
            
        Returns:
            Snapshot object or None if not found
        """
        for domain_dir in self.snapshots_dir.iterdir():
            if domain_dir.is_dir():
                for snapshot_dir in domain_dir.iterdir():
                    if snapshot_dir.is_dir():
                        metadata_file = snapshot_dir / "metadata.json"
                        if metadata_file.exists():
                            data = self._read_json_file(metadata_file)
                            snapshot = Snapshot.from_dict(data)
                            if snapshot.id == snapshot_id:
                                return snapshot
        return None
    
    def validate_snapshot(self, snapshot: Snapshot) -> tuple[bool, list[str]]:
        """Validate a snapshot's integrity.
        
        Args:
            snapshot: Snapshot to validate
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        return snapshot.validate_integrity(str(self.data_dir))
    
    def save_html(self, snapshot_dir: str, html_content: str) -> str:
        """Save HTML content to a file.
        
        Args:
            snapshot_dir: Directory where the snapshot is stored
            html_content: HTML content to save
            
        Returns:
            Relative path to the saved HTML file
        """
        html_file = Path(snapshot_dir) / "page.html"
        with open(html_file, 'w', encoding='utf-8', newline='') as f:
            f.write(html_content)
        
        return str(html_file.relative_to(self.data_dir))
    
    def load_html(self, html_path: str) -> str:
        """Load HTML content from a file.
        
        Args:
            html_path: Relative path to the HTML file
            
        Returns:
            HTML content as string
        """
        full_path = self.data_dir / html_path
        with open(full_path, 'r', encoding='utf-8', newline='') as f:
            return f.read()
    
    def append_ping_log(self, domain_id: str, entry: PingLogEntry) -> None:
        """Append a ping log entry to the domain's ping log.
        
        Args:
            domain_id: ID of the domain
            entry: PingLogEntry to append
        """
        domain_dir = self.snapshots_dir / domain_id
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = domain_dir / "ping.log"
        self._append_log_entry(log_file, entry.to_json())
    
    def read_ping_log(self, domain_id: str) -> List[PingLogEntry]:
        """Read all ping log entries for a domain.
        
        Args:
            domain_id: ID of the domain
            
        Returns:
            List of PingLogEntry objects ordered chronologically
        """
        domain_dir = self.snapshots_dir / domain_id
        log_file = domain_dir / "ping.log"
        
        if not log_file.exists():
            return []
        
        entries = []
        for line in log_file.read_text(encoding='utf-8').strip().split('\n'):
            if line:
                entries.append(PingLogEntry.from_json(line))
        
        return entries
    
    def append_dump_log(self, domain_id: str, entry: DumpLogEntry) -> None:
        """Append a dump log entry to the domain's dump log.
        
        Args:
            domain_id: ID of the domain
            entry: DumpLogEntry to append
        """
        domain_dir = self.snapshots_dir / domain_id
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = domain_dir / "dump.log"
        self._append_log_entry(log_file, entry.to_json())
    
    def read_dump_log(self, domain_id: str) -> List[DumpLogEntry]:
        """Read all dump log entries for a domain.
        
        Args:
            domain_id: ID of the domain
            
        Returns:
            List of DumpLogEntry objects ordered chronologically
        """
        domain_dir = self.snapshots_dir / domain_id
        log_file = domain_dir / "dump.log"
        
        if not log_file.exists():
            return []
        
        entries = []
        for line in log_file.read_text(encoding='utf-8').strip().split('\n'):
            if line:
                entries.append(DumpLogEntry.from_json(line))
        
        return entries
    
    def _read_json_file(self, file_path: Path) -> dict | list:
        """Read and parse a JSON file.
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            Parsed JSON data (empty list if file is empty or invalid)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except json.JSONDecodeError:
            import logging
            logging.warning(f"Invalid JSON in file {file_path}, returning empty list")
            return []
        except Exception as e:
            import logging
            logging.error(f"Error reading JSON file {file_path}: {e}")
            return []
    
    def _write_json_file(self, file_path: Path, data: dict | list) -> None:
        """Write data to a JSON file with proper formatting.
        
        Args:
            file_path: Path to the JSON file
            data: Data to write
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')  # Add trailing newline
    
    def _append_log_entry(self, log_file: Path, entry_json: str) -> None:
        """Append a log entry to a log file with file locking.
        
        Args:
            log_file: Path to the log file
            entry_json: JSON string of the log entry
        """
        with open(log_file, 'a', encoding='utf-8') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(entry_json + '\n')
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    
    def reset_environment(self) -> dict:
        """Reset the monitoring environment by clearing all data.
        
        This will:
        - Delete all groups
        - Delete all domains
        - Delete all snapshots and logs
        
        Returns:
            Dictionary with reset statistics
        """
        import shutil
        
        stats = {
            'groups_deleted': 0,
            'domains_deleted': 0,
            'snapshots_deleted': 0
        }
        
        if self.groups_file.exists():
            groups = self.load_groups()
            stats['groups_deleted'] = len(groups)
        
        if self.domains_file.exists():
            domains = self.load_domains()
            stats['domains_deleted'] = len(domains)
        
        if self.snapshots_dir.exists():
            for domain_dir in self.snapshots_dir.iterdir():
                if domain_dir.is_dir():
                    for snapshot_dir in domain_dir.iterdir():
                        if snapshot_dir.is_dir():
                            stats['snapshots_deleted'] += 1
        
        if self.groups_file.exists():
            self.groups_file.unlink()
        
        if self.domains_file.exists():
            self.domains_file.unlink()
        
        if self.snapshots_dir.exists():
            shutil.rmtree(self.snapshots_dir)
        
        self._ensure_directories()
        
        self._write_json_file(self.groups_file, [])
        self._write_json_file(self.domains_file, [])
        
        return stats

_storage_manager = None

def get_storage_manager() -> StorageManager:
    """Get the global storage manager instance.
    
    Returns:
        StorageManager instance
    """
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = StorageManager()
    return _storage_manager
