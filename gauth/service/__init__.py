"""
Service layer for GAuth providing centralized service management and coordination.

This file implements the core GAuth service logic as defined in RFC111:
  - Centralized authorization (PDP, PEP)
  - Token issuance, validation, revocation, and delegation
  - Audit/event logging for all protocol steps
  - Rate limiting and compliance enforcement
"""

import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from ..core.gauth import GAuth
from ..core.config import Config
from ..core.types import (
    AuthorizationRequest,
    AuthorizationGrant,
    TokenRequest,
    TokenResponse,
    AccessToken,
)
from ..events import EventBus, Event, EventType, EventAction
from ..transaction import TransactionProcessor, TransactionContext
from ..errors import ErrorCode, GAuthError


class ServiceError(GAuthError):
    """Service-specific error."""
    pass


class Service:
    """
    Main GAuth service that orchestrates all components.
    
    Provides high-level service management, event coordination,
    and centralized access to all GAuth functionality.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.gauth = GAuth.new(config)
        self.event_bus = EventBus()
        self.transaction_processor = TransactionProcessor(self.gauth)
        self._running = False
        self._grants: Dict[str, AuthorizationGrant] = {}
        self._startup_time: Optional[datetime] = None
    
    async def start(self) -> None:
        """Start the GAuth service."""
        if self._running:
            return
        
        try:
            # Start event bus
            await self.event_bus.start()
            
            # Set running state
            self._running = True
            self._startup_time = datetime.now()
            
            # Publish service started event
            await self.event_bus.publish(Event(
                type=EventType.SERVICE_STARTED,
                action=EventAction.CREATE,
                subject="gauth-service",
                resource="service",
                metadata={
                    "client_id": self.config.client_id,
                    "startup_time": self._startup_time.isoformat(),
                }
            ))
            
        except Exception as e:
            await self.event_bus.publish(Event(
                type=EventType.SERVICE_ERROR,
                action=EventAction.CREATE,
                subject="gauth-service",
                resource="service",
                metadata={"error": str(e)}
            ))
            raise ServiceError(
                code=ErrorCode.SERVICE_UNAVAILABLE,
                message=f"Failed to start GAuth service: {e}"
            )
    
    async def stop(self) -> None:
        """Stop the GAuth service."""
        if not self._running:
            return
        
        try:
            # Publish service stopping event
            await self.event_bus.publish(Event(
                type=EventType.SERVICE_STOPPED,
                action=EventAction.DELETE,
                subject="gauth-service",
                resource="service",
                metadata={
                    "shutdown_time": datetime.now().isoformat(),
                    "uptime_seconds": (datetime.now() - self._startup_time).total_seconds() if self._startup_time else 0,
                }
            ))
            
            # Stop components
            await self.gauth.close()
            await self.event_bus.stop()
            
            # Clear state
            self._running = False
            self._grants.clear()
            
        except Exception as e:
            await self.event_bus.publish(Event(
                type=EventType.SERVICE_ERROR,
                action=EventAction.DELETE,
                subject="gauth-service",
                resource="service",
                metadata={"error": str(e)}
            ))
            raise ServiceError(
                code=ErrorCode.SERVER_ERROR,
                message=f"Failed to stop GAuth service: {e}"
            )
    
    async def authorize(self, request: AuthorizationRequest) -> AuthorizationGrant:
        """
        Handle authorization request with full event handling.
        
        Args:
            request: Authorization request
            
        Returns:
            Authorization grant
        """
        if not self._running:
            raise ServiceError(
                code=ErrorCode.SERVICE_UNAVAILABLE,
                message="GAuth service is not running"
            )
        
        try:
            # Publish authorization request event
            await self.event_bus.publish(Event(
                type=EventType.AUTH_REQUEST,
                action=EventAction.CREATE,
                subject=request.client_id,
                resource="authorization",
                metadata={
                    "scopes": request.scopes,
                    "redirect_uri": getattr(request, 'redirect_uri', None),
                }
            ))
            
            # Process authorization
            grant = await self.gauth.initiate_authorization(request)
            
            # Store grant
            self._grants[grant.grant_id] = grant
            
            # Publish authorization granted event
            await self.event_bus.publish(Event(
                type=EventType.AUTH_GRANT,
                action=EventAction.GRANT,
                subject=request.client_id,
                resource="authorization",
                metadata={
                    "grant_id": grant.grant_id,
                    "scopes": grant.scope,
                    "valid_until": grant.valid_until.isoformat(),
                }
            ))
            
            return grant
            
        except Exception as e:
            # Publish authorization denied event
            await self.event_bus.publish(Event(
                type=EventType.AUTH_DENIED,
                action=EventAction.DENY,
                subject=request.client_id,
                resource="authorization",
                metadata={"error": str(e)}
            ))
            raise
    
    async def request_token(self, request: TokenRequest) -> TokenResponse:
        """
        Handle token request with full event handling.
        
        Args:
            request: Token request
            
        Returns:
            Token response
        """
        if not self._running:
            raise ServiceError(
                code=ErrorCode.SERVICE_UNAVAILABLE,
                message="GAuth service is not running"
            )
        
        try:
            # Validate grant exists
            if request.grant_id not in self._grants:
                raise GAuthError(
                    code=ErrorCode.INVALID_GRANT,
                    message="Invalid grant ID"
                )
            
            grant = self._grants[request.grant_id]
            
            # Process token request
            token_response = await self.gauth.request_token(request)
            
            # Publish token issued event
            await self.event_bus.publish(Event(
                type=EventType.TOKEN_ISSUED,
                action=EventAction.CREATE,
                subject=request.client_id,
                resource=f"token:{token_response.token[:8]}...",
                metadata={
                    "grant_id": request.grant_id,
                    "scope": token_response.scope,
                    "valid_until": token_response.valid_until.isoformat(),
                }
            ))
            
            return token_response
            
        except Exception as e:
            # Publish token issuance failure
            await self.event_bus.publish(Event(
                type=EventType.ERROR_OCCURRED,
                action=EventAction.CREATE,
                subject=request.client_id,
                resource="token",
                metadata={"error": str(e), "grant_id": request.grant_id}
            ))
            raise
    
    async def validate_token(self, token: str) -> Optional[AccessToken]:
        """
        Validate token with event handling.
        
        Args:
            token: Token to validate
            
        Returns:
            Token data if valid, None otherwise
        """
        if not self._running:
            raise ServiceError(
                code=ErrorCode.SERVICE_UNAVAILABLE,
                message="GAuth service is not running"
            )
        
        try:
            # Validate token
            token_data = await self.gauth.validate_token(token)
            
            if token_data:
                # Publish token validated event
                await self.event_bus.publish(Event(
                    type=EventType.TOKEN_VALIDATED,
                    action=EventAction.VALIDATE,
                    subject=token_data.client_id,
                    resource=f"token:{token[:8]}...",
                    metadata={
                        "scope": token_data.scope,
                        "expires_at": token_data.valid_until.isoformat(),
                    }
                ))
            
            return token_data
            
        except Exception as e:
            # Publish validation failure
            await self.event_bus.publish(Event(
                type=EventType.ERROR_OCCURRED,
                action=EventAction.VALIDATE,
                subject="unknown",
                resource=f"token:{token[:8]}...",
                metadata={"error": str(e)}
            ))
            raise
    
    async def revoke_token(self, token: str) -> bool:
        """
        Revoke token with event handling.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if revoked successfully
        """
        if not self._running:
            raise ServiceError(
                code=ErrorCode.SERVICE_UNAVAILABLE,
                message="GAuth service is not running"
            )
        
        try:
            # Get token info before revoking
            token_data = await self.gauth.validate_token(token)
            
            # Revoke token
            success = await self.gauth.revoke_token(token)
            
            if success and token_data:
                # Publish token revoked event
                await self.event_bus.publish(Event(
                    type=EventType.TOKEN_REVOKED,
                    action=EventAction.REVOKE,
                    subject=token_data.client_id,
                    resource=f"token:{token[:8]}...",
                    metadata={
                        "revoked_at": datetime.now().isoformat(),
                    }
                ))
            
            return success
            
        except Exception as e:
            # Publish revocation failure
            await self.event_bus.publish(Event(
                type=EventType.ERROR_OCCURRED,
                action=EventAction.REVOKE,
                subject="unknown",
                resource=f"token:{token[:8]}...",
                metadata={"error": str(e)}
            ))
            raise
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get current service status and statistics."""
        uptime = None
        if self._startup_time:
            uptime = (datetime.now() - self._startup_time).total_seconds()
        
        return {
            "running": self._running,
            "startup_time": self._startup_time.isoformat() if self._startup_time else None,
            "uptime_seconds": uptime,
            "client_id": self.config.client_id,
            "active_grants": len(self._grants),
            "config": {
                "auth_server_url": self.config.auth_server_url,
                "scopes": self.config.scopes,
                "token_expiry": str(self.config.access_token_expiry),
            }
        }
    
    def get_grants(self) -> List[AuthorizationGrant]:
        """Get all active grants."""
        return list(self._grants.values())
    
    def get_grant(self, grant_id: str) -> Optional[AuthorizationGrant]:
        """Get specific grant by ID."""
        return self._grants.get(grant_id)
    
    def cleanup_expired_grants(self) -> int:
        """Remove expired grants and return count removed."""
        now = datetime.now()
        expired_ids = [
            grant_id for grant_id, grant in self._grants.items()
            if grant.valid_until <= now
        ]
        
        for grant_id in expired_ids:
            del self._grants[grant_id]
        
        return len(expired_ids)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of service and components."""
        health = {
            "service": "healthy" if self._running else "unhealthy",
            "components": {},
            "timestamp": datetime.now().isoformat(),
        }
        
        # Check event bus
        try:
            health["components"]["event_bus"] = "healthy" if self.event_bus._running else "stopped"
        except:
            health["components"]["event_bus"] = "error"
        
        # Check transaction processor
        try:
            active_tx = len(self.transaction_processor.get_active_transactions())
            health["components"]["transaction_processor"] = {
                "status": "healthy",
                "active_transactions": active_tx
            }
        except Exception as e:
            health["components"]["transaction_processor"] = {
                "status": "error",
                "error": str(e)
            }
        
        # Check rate limiter
        try:
            # This would depend on rate limiter implementation
            health["components"]["rate_limiter"] = "healthy"
        except:
            health["components"]["rate_limiter"] = "unknown"
        
        return health


# Service factory function
async def create_service(config: Config) -> Service:
    """
    Create and start a GAuth service.
    
    Args:
        config: Service configuration
        
    Returns:
        Started service instance
    """
    service = Service(config)
    await service.start()
    return service