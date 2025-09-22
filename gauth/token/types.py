"""
Token types and structures for GAuth implementation.

This module provides the core token types including TokenData, EnhancedToken,
and related structures for RFC 115 compliance and GAuth protocol support.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import logging

logger = logging.getLogger(__name__)


class TokenStatus(Enum):
    """Token status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"
    INVALID = "invalid"


class TokenType(Enum):
    """Token type enumeration."""
    ACCESS = "access"
    REFRESH = "refresh"
    ID = "id"
    DELEGATION = "delegation"
    POA = "poa"  # Power of Attorney
    ENHANCED = "enhanced"


class Algorithm(Enum):
    """Cryptographic algorithms for token signing."""
    RS256 = "RS256"  # RSA with SHA-256
    ES256 = "ES256"  # ECDSA with SHA-256
    HS256 = "HS256"  # HMAC with SHA-256
    PS256 = "PS256"  # RSA-PSS with SHA-256


@dataclass
class DeviceInfo:
    """Information about the device using the token."""
    id: str
    user_agent: str = ""
    ip_address: str = ""
    platform: Optional[str] = None
    version: Optional[str] = None


@dataclass
class RevocationStatus:
    """Information about token revocation."""
    revoked_at: datetime
    reason: str
    revoked_by: Optional[str] = None


@dataclass
class Metadata:
    """Token metadata for additional context."""
    device: Optional[DeviceInfo] = None
    app_id: Optional[str] = None
    app_version: Optional[str] = None
    app_data: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class TokenData:
    """Core token data structure for GAuth protocol."""
    # Core identification
    token_id: str
    user_id: str  # Subject
    client_id: str
    
    # Authorization
    scopes: List[str] = field(default_factory=list)
    audience: List[str] = field(default_factory=list)
    
    # Timestamps
    issued_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    
    # Status and validity
    status: TokenStatus = TokenStatus.ACTIVE
    valid: bool = True
    
    # Token details
    token_type: TokenType = TokenType.ACCESS
    issuer: str = ""
    algorithm: Algorithm = Algorithm.RS256
    
    # Additional data
    metadata: Optional[Metadata] = None
    revocation_status: Optional[RevocationStatus] = None
    restrictions: Optional[Dict[str, Any]] = None
    
    def is_expired(self) -> bool:
        """Check if token has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if token is currently valid."""
        if not self.valid:
            return False
        if self.status != TokenStatus.ACTIVE:
            return False
        if self.is_expired():
            return False
        if self.not_before and datetime.now() < self.not_before:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "token_id": self.token_id,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "scopes": self.scopes,
            "audience": self.audience,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "status": self.status.value,
            "valid": self.valid,
            "token_type": self.token_type.value,
            "issuer": self.issuer,
            "algorithm": self.algorithm.value,
        }
        
        if self.metadata:
            result["metadata"] = {
                "device": self.metadata.device.__dict__ if self.metadata.device else None,
                "app_id": self.metadata.app_id,
                "app_version": self.metadata.app_version,
                "app_data": self.metadata.app_data,
                "labels": self.metadata.labels,
                "tags": self.metadata.tags,
                "attributes": self.metadata.attributes,
            }
        
        if self.revocation_status:
            result["revocation_status"] = {
                "revoked_at": self.revocation_status.revoked_at.isoformat(),
                "reason": self.revocation_status.reason,
                "revoked_by": self.revocation_status.revoked_by,
            }
        
        if self.restrictions:
            result["restrictions"] = self.restrictions
            
        return result


@dataclass
class OwnerInfo:
    """Information about the token owner and authorizer."""
    owner_id: str
    owner_type: str  # "client_owner" or "resource_owner"
    authorizer_id: Optional[str] = None
    authorization_ref: Optional[str] = None
    registration_info: Optional[Dict[str, Any]] = None


@dataclass
class Restrictions:
    """Restrictions on token usage."""
    ip_allow_list: List[str] = field(default_factory=list)
    time_window: Optional[str] = None
    start_time: Optional[str] = None  # 24h format (HH:MM)
    end_time: Optional[str] = None    # 24h format (HH:MM)
    days_of_week: List[int] = field(default_factory=list)  # 0 = Sunday, 6 = Saturday


@dataclass
class Attestation:
    """Required verification for enhanced tokens."""
    type: str  # e.g., "notary", "witness"
    attester_id: str
    attestation_date: datetime
    evidence: str = ""


@dataclass
class VersionInfo:
    """Track authority changes."""
    version: int
    updated_at: datetime
    updated_by: str
    change_type: str
    change_summary: str = ""


@dataclass
class AIMetadata:
    """AI-specific metadata for enhanced tokens."""
    successor_id: Optional[str] = None
    restrictions: Optional[Restrictions] = None
    delegation_guidelines: List[str] = field(default_factory=list)


@dataclass
class EnhancedToken:
    """Enhanced token with GAuth-specific fields."""
    # Base token data
    token_data: TokenData
    
    # Enhanced fields
    owner: Optional[OwnerInfo] = None
    ai: Optional[AIMetadata] = None
    attestations: List[Attestation] = field(default_factory=list)
    versions: List[VersionInfo] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """Check if the enhanced token has expired."""
        return self.token_data.is_expired()
    
    def is_valid(self) -> bool:
        """Check if the enhanced token is valid."""
        return self.token_data.is_valid()
    
    def add_attestation(self, attestation: Attestation) -> None:
        """Add an attestation to the token."""
        self.attestations.append(attestation)
    
    def add_version(self, version_info: VersionInfo) -> None:
        """Add version information to the token."""
        self.versions.append(version_info)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "token_data": self.token_data.to_dict(),
            "attestations": [
                {
                    "type": a.type,
                    "attester_id": a.attester_id,
                    "attestation_date": a.attestation_date.isoformat(),
                    "evidence": a.evidence,
                }
                for a in self.attestations
            ],
            "versions": [
                {
                    "version": v.version,
                    "updated_at": v.updated_at.isoformat(),
                    "updated_by": v.updated_by,
                    "change_type": v.change_type,
                    "change_summary": v.change_summary,
                }
                for v in self.versions
            ],
        }
        
        if self.owner:
            result["owner"] = {
                "owner_id": self.owner.owner_id,
                "owner_type": self.owner.owner_type,
                "authorizer_id": self.owner.authorizer_id,
                "authorization_ref": self.owner.authorization_ref,
                "registration_info": self.owner.registration_info,
            }
        
        if self.ai:
            result["ai"] = {
                "successor_id": self.ai.successor_id,
                "delegation_guidelines": self.ai.delegation_guidelines,
            }
            if self.ai.restrictions:
                result["ai"]["restrictions"] = {
                    "ip_allow_list": self.ai.restrictions.ip_allow_list,
                    "time_window": self.ai.restrictions.time_window,
                    "start_time": self.ai.restrictions.start_time,
                    "end_time": self.ai.restrictions.end_time,
                    "days_of_week": self.ai.restrictions.days_of_week,
                }
        
        return result


@dataclass
class DelegationOptions:
    """Options for creating delegated tokens."""
    principal: str        # The principal/owner granting authority
    scope: str           # Scope of the delegated power
    restrictions: Optional[Restrictions] = None  # Limits on the delegated power
    attestation: Optional[Attestation] = None    # Required attestation
    valid_until: Optional[datetime] = None       # Expiry of the delegation
    successor_id: Optional[str] = None           # Optional backup AI
    version: int = 1     # Version for tracking


def create_token_data(
    user_id: str,
    client_id: str,
    scopes: Optional[List[str]] = None,
    expires_in: Optional[timedelta] = None,
    **kwargs
) -> TokenData:
    """Create a new TokenData instance with defaults."""
    import uuid
    
    token_id = str(uuid.uuid4())
    now = datetime.now()
    
    return TokenData(
        token_id=token_id,
        user_id=user_id,
        client_id=client_id,
        scopes=scopes or [],
        issued_at=now,
        expires_at=now + expires_in if expires_in else None,
        **kwargs
    )


def create_enhanced_token(
    token_data: TokenData,
    owner: Optional[OwnerInfo] = None,
    **kwargs
) -> EnhancedToken:
    """Create a new EnhancedToken instance."""
    return EnhancedToken(
        token_data=token_data,
        owner=owner,
        **kwargs
    )


def create_delegated_token(agent_id: str, options: DelegationOptions) -> EnhancedToken:
    """Create an EnhancedToken for advanced delegation/attestation flows."""
    now = datetime.now()
    
    token_data = create_token_data(
        user_id=agent_id,  # RFC111: agent or AI being delegated to
        client_id="",      # Can be set if needed
        scopes=[options.scope],
        expires_in=timedelta(seconds=(options.valid_until - now).total_seconds()) if options.valid_until else None,
        token_type=TokenType.DELEGATION,
        issued_at=now,
    )
    
    owner = OwnerInfo(
        owner_id=options.principal,
        owner_type="client_owner"
    )
    
    ai_metadata = AIMetadata(
        successor_id=options.successor_id,
        restrictions=options.restrictions,
        delegation_guidelines=[],
    )
    
    attestations = [options.attestation] if options.attestation else []
    
    versions = [VersionInfo(
        version=options.version,
        updated_at=now,
        updated_by=options.principal,
        change_type="delegation_created",
        change_summary="Initial delegation issued.",
    )]
    
    return EnhancedToken(
        token_data=token_data,
        owner=owner,
        ai=ai_metadata,
        attestations=attestations,
        versions=versions,
    )