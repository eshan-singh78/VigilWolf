"""Data models for the Domain Monitoring System."""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Literal
from datetime import datetime
import json
import uuid

@dataclass
class Group:
    """Represents a monitoring group containing multiple domains."""
    id: str
    name: str
    created_at: str
    domain_ids: List[str] = field(default_factory=list)
    
    @staticmethod
    def create(name: str, domain_ids: List[str] = None) -> 'Group':
        """Create a new group with generated ID and timestamp."""
        return Group(
            id=str(uuid.uuid4()),
            name=name,
            created_at=datetime.utcnow().isoformat() + 'Z',
            domain_ids=domain_ids or []
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> 'Group':
        """Create Group from dictionary."""
        return Group(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @staticmethod
    def from_json(json_str: str) -> 'Group':
        """Create Group from JSON string."""
        return Group.from_dict(json.loads(json_str))

@dataclass
class Domain:
    """Represents a monitored domain with its configuration."""
    id: str
    group_id: str
    url: str
    dump_mode: Literal["html_only", "html_and_assets"]
    frequency_seconds: int
    created_at: str
    last_checked_at: Optional[str] = None
    active: bool = True
    
    @staticmethod
    def create(
        group_id: str,
        url: str,
        dump_mode: Literal["html_only", "html_and_assets"],
        frequency_seconds: int
    ) -> 'Domain':
        """Create a new domain with generated ID and timestamp."""
        return Domain(
            id=str(uuid.uuid4()),
            group_id=group_id,
            url=url,
            dump_mode=dump_mode,
            frequency_seconds=frequency_seconds,
            created_at=datetime.utcnow().isoformat() + 'Z'
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> 'Domain':
        """Create Domain from dictionary."""
        return Domain(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @staticmethod
    def from_json(json_str: str) -> 'Domain':
        """Create Domain from JSON string."""
        return Domain.from_dict(json.loads(json_str))

@dataclass
class Snapshot:
    """Represents a captured snapshot of a domain at a specific time."""
    id: str
    domain_id: str
    timestamp: str
    trigger_type: Literal["initial", "automatic", "manual"]
    html_path: str
    screenshot_path: Optional[str]
    assets_dir: Optional[str]
    asset_count: int
    success: bool
    error_message: Optional[str] = None
    
    @staticmethod
    def create(
        domain_id: str,
        trigger_type: Literal["initial", "automatic", "manual"],
        html_path: str,
        screenshot_path: Optional[str] = None,
        assets_dir: Optional[str] = None,
        asset_count: int = 0,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> 'Snapshot':
        """Create a new snapshot with generated ID and timestamp."""
        return Snapshot(
            id=str(uuid.uuid4()),
            domain_id=domain_id,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            trigger_type=trigger_type,
            html_path=html_path,
            screenshot_path=screenshot_path,
            assets_dir=assets_dir,
            asset_count=asset_count,
            success=success,
            error_message=error_message
        )
    
    def validate_integrity(self, data_dir: str) -> tuple[bool, list[str]]:
        """Validate snapshot integrity by checking that all referenced paths exist.
        
        Args:
            data_dir: Base data directory path
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        from pathlib import Path
        
        errors = []
        
        if self.html_path:
            html_file = Path(data_dir) / self.html_path
            if not html_file.exists():
                errors.append(f"HTML file does not exist: {self.html_path}")
            elif not html_file.is_file():
                errors.append(f"HTML path is not a file: {self.html_path}")
        else:
            if self.success:
                errors.append("HTML path is empty but snapshot marked as successful")
        
        if self.screenshot_path:
            screenshot_file = Path(data_dir) / self.screenshot_path
            if not screenshot_file.exists():
                pass
            elif not screenshot_file.is_file():
                errors.append(f"Screenshot path is not a file: {self.screenshot_path}")
        
        if self.assets_dir:
            assets_path = Path(data_dir) / self.assets_dir
            if not assets_path.exists():
                errors.append(f"Assets directory does not exist: {self.assets_dir}")
            elif not assets_path.is_dir():
                errors.append(f"Assets path is not a directory: {self.assets_dir}")
            else:
                actual_files = [f for f in assets_path.iterdir() if f.is_file()]
                if len(actual_files) != self.asset_count:
                    errors.append(
                        f"Asset count mismatch: metadata says {self.asset_count}, "
                        f"but found {len(actual_files)} files"
                    )
        elif self.asset_count > 0:
            errors.append(f"Asset count is {self.asset_count} but assets_dir is None")
        
        if self.html_path:
            html_parent = str(Path(self.html_path).parent)
            
            if self.screenshot_path:
                screenshot_parent = str(Path(self.screenshot_path).parent)
                if html_parent != screenshot_parent:
                    errors.append(
                        "HTML and screenshot are not in the same snapshot directory"
                    )
            
            if self.assets_dir:
                assets_parent = str(Path(self.assets_dir).parent)
                if html_parent != assets_parent:
                    errors.append(
                        "HTML and assets are not in the same snapshot directory"
                    )
        
        return len(errors) == 0, errors
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> 'Snapshot':
        """Create Snapshot from dictionary."""
        return Snapshot(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @staticmethod
    def from_json(json_str: str) -> 'Snapshot':
        """Create Snapshot from JSON string."""
        return Snapshot.from_dict(json.loads(json_str))

@dataclass
class PingLogEntry:
    """Represents a single ping log entry for domain availability checks."""
    timestamp: str
    reachable: bool
    status_code: Optional[int]
    change_detected: bool
    message: str
    
    @staticmethod
    def create(
        reachable: bool,
        status_code: Optional[int],
        change_detected: bool,
        message: str
    ) -> 'PingLogEntry':
        """Create a new ping log entry with current timestamp."""
        return PingLogEntry(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            reachable=reachable,
            status_code=status_code,
            change_detected=change_detected,
            message=message
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> 'PingLogEntry':
        """Create PingLogEntry from dictionary."""
        return PingLogEntry(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @staticmethod
    def from_json(json_str: str) -> 'PingLogEntry':
        """Create PingLogEntry from JSON string."""
        return PingLogEntry.from_dict(json.loads(json_str))

@dataclass
class DumpLogEntry:
    """Represents a single dump log entry for snapshot creation events."""
    timestamp: str
    trigger_type: Literal["automatic", "manual", "initial"]
    snapshot_id: str
    success: bool
    error_message: Optional[str]
    message: str
    
    @staticmethod
    def create(
        trigger_type: Literal["automatic", "manual", "initial"],
        snapshot_id: str,
        success: bool,
        message: str,
        error_message: Optional[str] = None
    ) -> 'DumpLogEntry':
        """Create a new dump log entry with current timestamp."""
        return DumpLogEntry(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            trigger_type=trigger_type,
            snapshot_id=snapshot_id,
            success=success,
            error_message=error_message,
            message=message
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> 'DumpLogEntry':
        """Create DumpLogEntry from dictionary."""
        return DumpLogEntry(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @staticmethod
    def from_json(json_str: str) -> 'DumpLogEntry':
        """Create DumpLogEntry from JSON string."""
        return DumpLogEntry.from_dict(json.loads(json_str))
