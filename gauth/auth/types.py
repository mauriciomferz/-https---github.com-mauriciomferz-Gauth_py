"""
Core authentication types and interfaces for GAuth protocol.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import time


class AuthType(Enum):
    """Authentication type enumeration."""
    BASIC = "basic"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    PASETO = "paseto"


@dataclass
class Claims:
    """JWT/PASETO claims."""
    iss: Optional[str] = None  # Issuer
    sub: Optional[str] = None  # Subject
    aud: Optional[Union[str, List[str]]] = None  # Audience
    exp: Optional[int] = None  # Expiration time
    nbf: Optional[int] = None  # Not before
    iat: Optional[int] = None  # Issued at
    jti: Optional[str] = None  # JWT ID
    
    # Custom claims
    scope: Optional[str] = None
    role: Optional[str] = None
    permissions: Optional[List[str]] = None
    custom: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {}
        
        # Standard claims
        if self.iss is not None:
            result['iss'] = self.iss
        if self.sub is not None:
            result['sub'] = self.sub
        if self.aud is not None:
            result['aud'] = self.aud
        if self.exp is not None:
            result['exp'] = self.exp
        if self.nbf is not None:
            result['nbf'] = self.nbf
        if self.iat is not None:
            result['iat'] = self.iat
        if self.jti is not None:
            result['jti'] = self.jti
            
        # Custom claims
        if self.scope is not None:
            result['scope'] = self.scope
        if self.role is not None:
            result['role'] = self.role
        if self.permissions is not None:
            result['permissions'] = self.permissions
            
        # Custom data
        result.update(self.custom)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Claims':
        """Create from dictionary."""
        standard_fields = {'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'scope', 'role', 'permissions'}
        
        kwargs = {}
        custom = {}
        
        for key, value in data.items():
            if key in standard_fields:
                kwargs[key] = value
            else:
                custom[key] = value
        
        if custom:
            kwargs['custom'] = custom
            
        return cls(**kwargs)


@dataclass
class TokenValidationConfig:
    """Token validation configuration."""
    allowed_issuers: List[str] = field(default_factory=list)
    allowed_audiences: List[str] = field(default_factory=list)
    required_scopes: List[str] = field(default_factory=list)
    required_claims: Optional[Claims] = None
    clock_skew: timedelta = field(default_factory=lambda: timedelta(seconds=300))
    validate_signature: bool = True
    validate_expiration: bool = True
    validate_not_before: bool = True
    validate_issued_at: bool = True


@dataclass
class ApprovalRule:
    """Approval rule for compliance."""
    id: str
    name: str
    description: str
    condition: str
    action: str
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Metadata:
    """Request metadata."""
    ip_address: Optional[str] = None
    device: Optional[str] = None
    user_agent: Optional[str] = None
    custom_data: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'ip_address': self.ip_address,
            'device': self.device,
            'user_agent': self.user_agent,
            'custom_data': self.custom_data
        }


@dataclass
class TokenRequest:
    """Token generation request."""
    grant_type: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    scope: Optional[str] = None
    audience: Optional[str] = None
    subject: Optional[str] = None
    expires_in: Optional[int] = None
    metadata: Optional[Metadata] = None
    custom_claims: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'grant_type': self.grant_type,
            'custom_claims': self.custom_claims
        }
        
        if self.client_id is not None:
            result['client_id'] = self.client_id
        if self.client_secret is not None:
            result['client_secret'] = self.client_secret
        if self.username is not None:
            result['username'] = self.username
        if self.password is not None:
            result['password'] = self.password
        if self.scope is not None:
            result['scope'] = self.scope
        if self.audience is not None:
            result['audience'] = self.audience
        if self.subject is not None:
            result['subject'] = self.subject
        if self.expires_in is not None:
            result['expires_in'] = self.expires_in
        if self.metadata is not None:
            result['metadata'] = self.metadata.to_dict()
            
        return result


@dataclass
class TokenResponse:
    """Token generation response."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    issued_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'metadata': self.metadata
        }
        
        if self.expires_in is not None:
            result['expires_in'] = self.expires_in
        if self.refresh_token is not None:
            result['refresh_token'] = self.refresh_token
        if self.scope is not None:
            result['scope'] = self.scope
        if self.issued_at is not None:
            result['issued_at'] = self.issued_at.isoformat()
            
        return result


@dataclass
class TokenData:
    """Validated token data."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[Union[str, List[str]]] = None
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    token_id: Optional[str] = None
    scope: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self, clock_skew: timedelta = timedelta(seconds=300)) -> bool:
        """Check if token is still valid."""
        now = datetime.utcnow()
        
        # Check expiration
        if self.expires_at and now > (self.expires_at + clock_skew):
            return False
            
        # Check not before
        if self.not_before and now < (self.not_before - clock_skew):
            return False
            
        return True
    
    def has_scope(self, required_scope: str) -> bool:
        """Check if token has required scope."""
        if not self.scope:
            return False
        
        scopes = self.scope.split()
        return required_scope in scopes
    
    def has_claim(self, claim_name: str, claim_value: Any = None) -> bool:
        """Check if token has required claim."""
        if claim_name not in self.claims:
            return False
            
        if claim_value is not None:
            return self.claims[claim_name] == claim_value
            
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'claims': self.claims,
            'metadata': self.metadata
        }
        
        if self.subject is not None:
            result['subject'] = self.subject
        if self.issuer is not None:
            result['issuer'] = self.issuer
        if self.audience is not None:
            result['audience'] = self.audience
        if self.expires_at is not None:
            result['expires_at'] = self.expires_at.isoformat()
        if self.issued_at is not None:
            result['issued_at'] = self.issued_at.isoformat()
        if self.not_before is not None:
            result['not_before'] = self.not_before.isoformat()
        if self.token_id is not None:
            result['token_id'] = self.token_id
        if self.scope is not None:
            result['scope'] = self.scope
            
        return result


@dataclass
class ValidationResult:
    """Token validation result."""
    valid: bool
    token_data: Optional[TokenData] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    validated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'valid': self.valid,
            'validated_at': self.validated_at.isoformat()
        }
        
        if self.token_data is not None:
            result['token_data'] = self.token_data.to_dict()
        if self.error_message is not None:
            result['error_message'] = self.error_message
        if self.error_code is not None:
            result['error_code'] = self.error_code
            
        return result


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: AuthType
    auth_server_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    access_token_expiry: timedelta = field(default_factory=lambda: timedelta(hours=1))
    token_validation: Optional[TokenValidationConfig] = None
    approval_rules: List[ApprovalRule] = field(default_factory=list)
    extra_config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'auth_type': self.auth_type.value,
            'scopes': self.scopes,
            'access_token_expiry': int(self.access_token_expiry.total_seconds()),
            'approval_rules': [rule.__dict__ for rule in self.approval_rules],
            'extra_config': self.extra_config
        }
        
        if self.auth_server_url is not None:
            result['auth_server_url'] = self.auth_server_url
        if self.client_id is not None:
            result['client_id'] = self.client_id
        if self.client_secret is not None:
            result['client_secret'] = self.client_secret
        if self.token_validation is not None:
            result['token_validation'] = self.token_validation.__dict__
            
        return result


class Authenticator(ABC):
    """Abstract authenticator interface."""
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the authenticator."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the authenticator and release resources."""
        pass
    
    @abstractmethod
    async def validate_credentials(self, credentials: Any) -> bool:
        """Validate credentials."""
        pass
    
    @abstractmethod
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate a new token."""
        pass
    
    @abstractmethod
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate a token."""
        pass
    
    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        pass