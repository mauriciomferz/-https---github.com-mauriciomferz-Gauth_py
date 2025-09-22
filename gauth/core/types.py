"""
Core types and data structures for the GAuth protocol.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

GAuth Protocol Compliance: This file implements the GAuth protocol (GiFo-RfC 0111).
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid


class ScopeType(Enum):
    """Standard GAuth scope types"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    TRANSACTION_EXECUTE = "transaction:execute"
    ADMIN = "admin"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    max_requests: int = 100
    time_window: timedelta = field(default_factory=lambda: timedelta(minutes=1))
    burst_limit: int = 10


@dataclass
class TokenConfig:
    """Token configuration settings"""
    algorithm: str = "HS256"
    secret_key: str = ""
    issuer: str = "gauth-py"
    audience: str = "gauth-client"


@dataclass
class Config:
    """Configuration for GAuth protocol implementation"""
    auth_server_url: str
    client_id: str
    client_secret: str
    scopes: List[str] = field(default_factory=list)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    access_token_expiry: timedelta = field(default_factory=lambda: timedelta(hours=1))
    token_config: Optional[TokenConfig] = None

    def __post_init__(self):
        if self.token_config is None:
            self.token_config = TokenConfig(secret_key=self.client_secret)


@dataclass
class Restriction:
    """Represents a restriction on authorization or token usage"""
    type: str  # e.g., "ip", "time_window", "resource"
    value: str  # The restriction value
    description: Optional[str] = None


@dataclass
class Attestation:
    """Represents a notary or witness attestation for a grant"""
    notary: str  # Notary or witness identifier
    version: str  # Attestation version
    issued_at: datetime  # When attestation was issued


@dataclass
class GrantVersion:
    """Represents a historical version of an AuthorizationGrant"""
    version: int
    changed_at: datetime
    changed_by: str  # Principal who made the change
    description: str  # Description of the change


@dataclass
class AuthorizationRequest:
    """Request to initiate authorization (delegation)"""
    client_id: str  # Unique client identifier
    scopes: List[str]  # Requested scopes/permissions
    redirect_uri: Optional[str] = None
    state: Optional[str] = None


@dataclass
class TokenRequest:
    """Request for a token"""
    grant_id: str  # Authorization grant ID
    scope: List[str]  # Requested scopes
    restrictions: List[Restriction] = field(default_factory=list)
    client_id: Optional[str] = None


@dataclass
class AuthorizationGrant:
    """Granted authorization - represents all delegation and power-of-attorney relationships"""
    grant_id: str
    client_id: str
    scope: List[str]
    restrictions: List[Restriction] = field(default_factory=list)
    valid_until: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=1))
    
    # Delegation: If this grant is delegated from another principal
    delegated_from: Optional[str] = None  # Principal who delegated authority
    
    # Revocation: If this grant is revoked
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None  # Principal who revoked
    
    # Attestation: Optional notary/witness attestation for high-assurance delegation
    attestation: Optional[Attestation] = None
    
    # Version history: Track changes to the grant for auditability
    version: int = 1
    version_log: List[GrantVersion] = field(default_factory=list)

    def __post_init__(self):
        if not self.grant_id:
            self.grant_id = str(uuid.uuid4())


@dataclass
class TokenResponse:
    """Response to a token request"""
    token: str
    valid_until: datetime
    scope: List[str]
    restrictions: List[Restriction] = field(default_factory=list)
    token_type: str = "Bearer"


@dataclass
class AccessToken:
    """Represents an access token"""
    token: str
    client_id: str
    scope: List[str]
    expires_at: datetime
    issued_at: datetime = field(default_factory=datetime.now)
    restrictions: List[Restriction] = field(default_factory=list)
    
    @property
    def is_expired(self) -> bool:
        """Check if the token is expired"""
        return datetime.now() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and has required fields)"""
        return not self.is_expired and bool(self.token and self.client_id)


@dataclass
class Transaction:
    """Represents a transaction to be processed"""
    transaction_id: str
    client_id: str
    action: str  # The action to perform
    resource: str  # The resource to act upon
    parameters: Dict[str, Any] = field(default_factory=dict)
    scope_required: List[str] = field(default_factory=list)
    restrictions: List[Restriction] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4())


@dataclass
class TransactionResult:
    """Result of a transaction execution"""
    transaction_id: str
    success: bool
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_at: datetime = field(default_factory=datetime.now)
    execution_time_ms: Optional[float] = None


@dataclass
class AuditEvent:
    """Audit event for logging and compliance"""
    event_id: str
    event_type: str  # e.g., "authorization", "token_issued", "transaction"
    client_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    principal: Optional[str] = None  # The principal involved
    resource: Optional[str] = None  # The resource involved
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid.uuid4())


# Error types
class GAuthError(Exception):
    """Base exception for GAuth protocol errors"""
    pass


class AuthorizationError(GAuthError):
    """Error during authorization process"""
    pass


class TokenError(GAuthError):
    """Error during token operations"""
    pass


class ValidationError(GAuthError):
    """Error during validation"""
    pass


class RateLimitError(GAuthError):
    """Error when rate limit is exceeded"""
    pass


class TransactionError(GAuthError):
    """Error during transaction processing"""
    pass