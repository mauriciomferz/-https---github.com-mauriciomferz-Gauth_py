"""
Main GAuth service implementation.

This module provides the core GAuth service that orchestrates all authentication,
authorization, and token management functionality according to RFC 115.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from ..auth.service import AuthService
from ..auth.types import AuthorizationRequest, TokenRequest, TokenResponse
from ..token.types import TokenData
from ..tokenstore.store import TokenStore
from ..audit.logger import AuditLogger
from ..common.config import Config
from ..errors.exceptions import GAuthError, AuthorizationError, TokenError

logger = logging.getLogger(__name__)


@dataclass
class ServiceConfig:
    """Configuration for the main GAuth service."""
    auth_server_url: str = "https://auth.example.com"
    client_id: str = ""
    client_secret: str = ""
    scopes: List[str] = field(default_factory=list)
    access_token_expiry: timedelta = field(default_factory=lambda: timedelta(hours=1))
    refresh_token_expiry: timedelta = field(default_factory=lambda: timedelta(days=30))
    
    # Rate limiting
    requests_per_second: int = 10
    burst_size: int = 5
    
    # Security
    require_https: bool = True
    token_signing_key: Optional[str] = None


@dataclass
class AuthorizationGrant:
    """Represents an authorization grant."""
    grant_id: str
    client_id: str
    scopes: List[str]
    expires_at: datetime
    redirect_uri: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if the grant has expired."""
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "grant_id": self.grant_id,
            "client_id": self.client_id,
            "scopes": self.scopes,
            "expires_at": self.expires_at.isoformat(),
            "redirect_uri": self.redirect_uri,
            "state": self.state,
            "code_challenge": self.code_challenge,
        }


@dataclass
class ServiceStatus:
    """Service status information."""
    running: bool = False
    start_time: Optional[datetime] = None
    active_tokens: int = 0
    active_grants: int = 0
    total_requests: int = 0
    error_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "running": self.running,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "active_tokens": self.active_tokens,
            "active_grants": self.active_grants,
            "total_requests": self.total_requests,
            "error_count": self.error_count,
        }


class GAuthService:
    """
    Main GAuth service that orchestrates all components.
    
    Provides high-level service management, event coordination,
    and centralized access to all GAuth functionality according to RFC 115.
    """
    
    def __init__(self, config: ServiceConfig, token_store: Optional[TokenStore] = None, 
                 audit_logger: Optional[AuditLogger] = None):
        """Initialize the GAuth service."""
        self.config = config
        self.token_store = token_store
        self.audit_logger = audit_logger
        
        # Service state
        self.status = ServiceStatus()
        self.grants: Dict[str, AuthorizationGrant] = {}
        self.clients: Dict[str, Dict[str, Any]] = {}
        
        # Initialize components
        self.auth_service = AuthService()
        
        logger.info("GAuth service initialized")
    
    async def start(self) -> None:
        """Start the GAuth service."""
        try:
            self.status.running = True
            self.status.start_time = datetime.now()
            
            if self.audit_logger:
                await self.audit_logger.log_event("service_start", {
                    "service": "gauth",
                    "timestamp": self.status.start_time.isoformat()
                })
            
            logger.info("GAuth service started successfully")
            
        except Exception as e:
            self.status.running = False
            logger.error(f"Failed to start GAuth service: {e}")
            raise GAuthError(f"Service startup failed: {e}")
    
    async def stop(self) -> None:
        """Stop the GAuth service."""
        try:
            self.status.running = False
            
            if self.audit_logger:
                await self.audit_logger.log_event("service_stop", {
                    "service": "gauth",
                    "timestamp": datetime.now().isoformat()
                })
            
            logger.info("GAuth service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping GAuth service: {e}")
            raise GAuthError(f"Service shutdown failed: {e}")
    
    async def initiate_authorization(self, request: AuthorizationRequest) -> AuthorizationGrant:
        """
        Initiate an authorization request.
        
        Args:
            request: Authorization request details
            
        Returns:
            Authorization grant
            
        Raises:
            AuthorizationError: If authorization fails
        """
        try:
            self.status.total_requests += 1
            
            # Validate the request
            if not request.client_id:
                raise AuthorizationError("Client ID is required")
            
            if not request.scopes:
                raise AuthorizationError("At least one scope is required")
            
            # Generate grant
            import uuid
            grant_id = str(uuid.uuid4())
            
            grant = AuthorizationGrant(
                grant_id=grant_id,
                client_id=request.client_id,
                scopes=request.scopes,
                expires_at=datetime.now() + timedelta(minutes=10),  # Short-lived grant
                redirect_uri=getattr(request, 'redirect_uri', None),
                state=getattr(request, 'state', None),
                code_challenge=getattr(request, 'code_challenge', None),
            )
            
            # Store the grant
            self.grants[grant_id] = grant
            self.status.active_grants = len(self.grants)
            
            # Audit log
            if self.audit_logger:
                await self.audit_logger.log_event("authorization_initiated", {
                    "grant_id": grant_id,
                    "client_id": request.client_id,
                    "scopes": request.scopes,
                })
            
            logger.info(f"Authorization granted: {grant_id}")
            return grant
            
        except Exception as e:
            self.status.error_count += 1
            logger.error(f"Authorization failed: {e}")
            raise AuthorizationError(f"Authorization failed: {e}")
    
    async def request_token(self, request: TokenRequest) -> TokenResponse:
        """
        Request an access token using an authorization grant.
        
        Args:
            request: Token request details
            
        Returns:
            Token response
            
        Raises:
            TokenError: If token generation fails
        """
        try:
            self.status.total_requests += 1
            
            # Validate grant
            grant_id = getattr(request, 'grant_id', None)
            if not grant_id:
                raise TokenError("Grant ID is required")
            
            grant = self.grants.get(grant_id)
            if not grant:
                raise TokenError("Invalid grant")
            
            if grant.is_expired:
                raise TokenError("Grant has expired")
            
            # Generate token
            token_response = await self.auth_service.generate_token(request)
            
            # Update status
            if self.token_store:
                self.status.active_tokens = len(await self.token_store.get_active_tokens())
            
            # Audit log
            if self.audit_logger:
                await self.audit_logger.log_event("token_issued", {
                    "grant_id": grant_id,
                    "client_id": grant.client_id,
                    "token_type": token_response.token_type,
                })
            
            logger.info(f"Token issued for grant: {grant_id}")
            return token_response
            
        except Exception as e:
            self.status.error_count += 1
            logger.error(f"Token request failed: {e}")
            raise TokenError(f"Token request failed: {e}")
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """
        Validate an access token.
        
        Args:
            token: Token string to validate
            
        Returns:
            Token data if valid, None otherwise
        """
        try:
            self.status.total_requests += 1
            
            # Use auth service to validate
            token_data = await self.auth_service.validate_token(token)
            
            # Audit log
            if self.audit_logger:
                await self.audit_logger.log_event("token_validated", {
                    "token_valid": token_data is not None,
                    "user_id": token_data.user_id if token_data else None,
                })
            
            return token_data
            
        except Exception as e:
            self.status.error_count += 1
            logger.error(f"Token validation failed: {e}")
            return None
    
    async def revoke_token(self, token: str, reason: str = "user_requested") -> bool:
        """
        Revoke an access token.
        
        Args:
            token: Token string to revoke
            reason: Reason for revocation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.status.total_requests += 1
            
            # Use auth service to revoke
            success = await self.auth_service.revoke_token(token, reason)
            
            # Update status
            if success and self.token_store:
                self.status.active_tokens = len(await self.token_store.get_active_tokens())
            
            # Audit log
            if self.audit_logger:
                await self.audit_logger.log_event("token_revoked", {
                    "success": success,
                    "reason": reason,
                })
            
            if success:
                logger.info(f"Token revoked: {reason}")
            else:
                logger.warning(f"Token revocation failed: {reason}")
                
            return success
            
        except Exception as e:
            self.status.error_count += 1
            logger.error(f"Token revocation failed: {e}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get current service status and statistics."""
        return self.status.to_dict()
    
    def get_grants(self) -> List[AuthorizationGrant]:
        """Get all active grants."""
        now = datetime.now()
        active_grants = [grant for grant in self.grants.values() if not grant.is_expired]
        
        # Clean up expired grants
        expired_grants = [gid for gid, grant in self.grants.items() if grant.is_expired]
        for gid in expired_grants:
            del self.grants[gid]
        
        self.status.active_grants = len(active_grants)
        return active_grants
    
    def register_client(self, client_id: str, client_data: Dict[str, Any]) -> None:
        """Register a client application."""
        self.clients[client_id] = {
            **client_data,
            "registered_at": datetime.now().isoformat(),
        }
        logger.info(f"Client registered: {client_id}")
    
    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information."""
        return self.clients.get(client_id)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check on the service."""
        health = {
            "status": "healthy" if self.status.running else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": 0,
            "components": {
                "auth_service": "healthy",
                "token_store": "healthy" if self.token_store else "not_configured",
                "audit_logger": "healthy" if self.audit_logger else "not_configured",
            }
        }
        
        if self.status.start_time:
            uptime = datetime.now() - self.status.start_time
            health["uptime_seconds"] = int(uptime.total_seconds())
        
        return health


def create_service(config: ServiceConfig, **kwargs) -> GAuthService:
    """
    Factory function to create a GAuth service instance.
    
    Args:
        config: Service configuration
        **kwargs: Additional configuration options
        
    Returns:
        Configured GAuth service instance
    """
    return GAuthService(config, **kwargs)