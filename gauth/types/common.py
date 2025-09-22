"""
Common types and utilities shared across GAuth packages.
Provides core identifiers, status types, and time utilities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import NewType, Union, Dict, Any, Optional
import uuid


# Core identifier types
UserID = NewType('UserID', str)
SessionID = NewType('SessionID', str)
TransactionID = NewType('TransactionID', str)
RequestID = NewType('RequestID', str)


class Status(str, Enum):
    """Generic status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"
    
    def __str__(self) -> str:
        return self.value


@dataclass
class AuditContext:
    """Context information for audit logging."""
    # Actor information
    actor_id: str = ""
    actor_type: str = ""
    session_id: str = ""
    
    # Action details
    action: str = ""
    resource: str = ""
    result: str = ""
    
    # Context information
    request_id: str = ""
    trace_id: str = ""
    source: str = ""
    
    # Additional details
    message: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    
    # Network information
    ip_address: str = ""
    user_agent: str = ""
    location: str = ""
    
    # Timestamps
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class ErrorLevel(str, Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __str__(self) -> str:
        return self.value


class LogLevel(str, Enum):
    """Logging levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    
    def __str__(self) -> str:
        return self.value


# Time utilities
Timestamp = datetime
Duration = timedelta


# Common constants
DEFAULT_TIMEOUT = timedelta(seconds=30)
MAX_RETRY_ATTEMPTS = 3
DEFAULT_PAGE_SIZE = 20


def generate_user_id() -> UserID:
    """Generate a new user ID."""
    return UserID(f"user_{uuid.uuid4().hex[:8]}")


def generate_session_id() -> SessionID:
    """Generate a new session ID."""
    return SessionID(f"sess_{uuid.uuid4().hex}")


def generate_transaction_id() -> TransactionID:
    """Generate a new transaction ID."""
    return TransactionID(f"txn_{uuid.uuid4().hex[:16]}")


def generate_request_id() -> RequestID:
    """Generate a new request ID."""
    return RequestID(f"req_{uuid.uuid4().hex[:12]}")


def is_expired(timestamp: Timestamp, ttl: Duration) -> bool:
    """Check if a timestamp has expired based on TTL."""
    return datetime.now() > (timestamp + ttl)


def time_until_expiry(timestamp: Timestamp, ttl: Duration) -> Duration:
    """Calculate time until expiry."""
    expiry_time = timestamp + ttl
    remaining = expiry_time - datetime.now()
    return max(remaining, timedelta(0))


def format_duration(duration: Duration) -> str:
    """Format a duration in a human-readable way."""
    seconds = int(duration.total_seconds())
    
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def parse_duration(duration_str: str) -> Duration:
    """Parse a duration string like '30s', '5m', '2h'."""
    duration_str = duration_str.strip().lower()
    
    if duration_str.endswith('s'):
        seconds = int(duration_str[:-1])
        return timedelta(seconds=seconds)
    elif duration_str.endswith('m'):
        minutes = int(duration_str[:-1])
        return timedelta(minutes=minutes)
    elif duration_str.endswith('h'):
        hours = int(duration_str[:-1])
        return timedelta(hours=hours)
    elif duration_str.endswith('d'):
        days = int(duration_str[:-1])
        return timedelta(days=days)
    else:
        # Assume seconds if no unit
        seconds = int(duration_str)
        return timedelta(seconds=seconds)