"""
Authentication service for GAuth.

This module provides the main authentication service that coordinates
all authentication methods and token management.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .auth import GAuthAuthenticator
try:  # optional metrics
    from ..monitoring import (
        increment_counter,
        set_gauge,
        METRIC_TOKENS_ISSUED,
        METRIC_TOKEN_VALIDATIONS,
        METRIC_ACTIVE_TOKENS,
    )
except Exception:  # pragma: no cover - metrics optional
    increment_counter = None  # type: ignore
    set_gauge = None  # type: ignore
    METRIC_TOKENS_ISSUED = "tokens_issued_total"  # type: ignore
    METRIC_TOKEN_VALIDATIONS = "token_validations_total"  # type: ignore
    METRIC_ACTIVE_TOKENS = "active_tokens"  # type: ignore
from ..token.rotation import RotationManager, RotationPolicy
from .types import AuthConfig, AuthType, TokenRequest, TokenResponse, TokenData
from .verification import verify_token_data
from .errors import AuthError, TokenError, ValidationError
from ..token.types import create_token_data
from ..errors import GAuthError
try:
    from ..policy.registry import (
        PolicyRegistry,
        PolicyContext,
        PolicyPhase,
        PolicyViolation,
    )
except Exception:  # pragma: no cover - policy module optional
    PolicyRegistry = None  # type: ignore
    PolicyContext = None  # type: ignore
    PolicyPhase = None  # type: ignore
    PolicyViolation = Exception  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class AuthServiceConfig:
    """Configuration for the authentication service."""
    auth_type: AuthType = AuthType.JWT
    secret_key: str = "default-secret-key"
    access_token_expiry: timedelta = timedelta(hours=1)
    issuer: Optional[str] = None
    audience: Optional[str] = None
    extra_config: Dict[str, Any] = None
    
    def to_auth_config(self) -> AuthConfig:
        """Convert to AuthConfig."""
        extra = dict(self.extra_config or {})
        # Ensure critical JWT-related config propagated
        extra.setdefault('secret_key', self.secret_key)
        if self.issuer:
            extra.setdefault('issuer', self.issuer)
        if self.audience:
            extra.setdefault('audience', self.audience)
        return AuthConfig(
            auth_type=self.auth_type,
            access_token_expiry=self.access_token_expiry,
            extra_config=extra
        )


class AuthService:
    """
    Main authentication service that provides token generation, validation, and revocation.
    """
    
    def __init__(self, config: Optional[AuthServiceConfig] = None, enable_rotation: bool = False, rotation_policy: Optional[RotationPolicy] = None, policy_registry: Optional["PolicyRegistry"] = None):
        """Initialize the authentication service."""
        self.config = config or AuthServiceConfig()
        self.rotation_manager: Optional[RotationManager] = RotationManager(rotation_policy) if enable_rotation else None
        # Pass rotation manager to JWT manager through authenticator by injecting into auth config extra
        auth_config = self.config.to_auth_config()
        if self.rotation_manager:
            # Signal to underlying managers (only JWT currently) that rotation is enabled
            auth_config.extra_config['__rotation_manager__'] = self.rotation_manager
        self.authenticator = GAuthAuthenticator(auth_config)
        self._initialized = False
        self._active_tokens: Dict[str, TokenData] = {}
        self._policy_registry: Optional[PolicyRegistry] = policy_registry
        
    async def initialize(self) -> None:
        """Initialize the authentication service."""
        if self._initialized:
            return
            
        try:
            await self.authenticator.initialize()
            self._initialized = True
            logger.info("Authentication service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize authentication service: {e}")
            raise AuthError(f"Initialization failed: {e}")
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """
        Generate an access token.
        
        Args:
            request: Token request details
            
        Returns:
            Token response with access token
            
        Raises:
            TokenError: If token generation fails
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Pre-issuance policy enforcement (if registry provided)
            if self._policy_registry and PolicyContext:
                ctx = PolicyContext(
                    phase=PolicyPhase.ISSUANCE,
                    request={
                        "subject": request.subject,
                        "scope": request.scope,
                        "audience": request.audience,
                        "client_id": getattr(request, 'client_id', None),
                    },
                    claims={},
                    metadata={},
                )
                try:
                    self._policy_registry.enforce(ctx)
                except PolicyViolation as pv:  # pragma: no cover - simple mapping
                    raise TokenError(f"Policy violation during issuance: {pv}") from pv

            # Generate token using authenticator
            token_response = await self.authenticator.generate_token(request)
            
            # Create token data for tracking
            token_data = create_token_data(
                user_id=request.subject or "unknown",
                client_id=getattr(request, 'client_id', 'unknown'),
                scopes=request.scope.split() if request.scope else [],
                expires_in=self.config.access_token_expiry
            )
            
            # Store token data
            self._active_tokens[token_response.access_token] = token_data
            
            logger.info(f"Token generated for subject: {request.subject}")
            # Metrics
            if increment_counter:
                try:
                    increment_counter(METRIC_TOKENS_ISSUED, 1)
                except Exception:  # pragma: no cover
                    pass
            if set_gauge:
                try:
                    set_gauge(METRIC_ACTIVE_TOKENS, float(len(self._active_tokens)))
                except Exception:  # pragma: no cover
                    pass
            return token_response
            
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            raise TokenError(f"Token generation failed: {e}")
    
    async def validate_token(self, token: str, *, required_scopes: Optional[List[str]] = None, expected_audiences: Optional[List[str]] = None, required_claims: Optional[Dict[str, Any]] = None, policy_metadata: Optional[Dict[str, Any]] = None) -> Optional[TokenData]:
        """
        Validate an access token.
        
        Args:
            token: Token string to validate
            
        Returns:
            Token data if valid, None otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Check if token is in our active tokens
            if token in self._active_tokens:
                token_data = self._active_tokens[token]
                # Check if token is still valid
                if token_data.is_valid():
                    # Validate using authenticator (authoritative signature/claims)
                    validation_result = await self.authenticator.validate_token(token)
                    if validation_result and validation_result.valid and validation_result.token_data:
                        outcome = verify_token_data(
                            validation_result.token_data,
                            expected_audiences=expected_audiences,
                            required_scopes=required_scopes,
                            required_claims=required_claims,
                        )
                        if outcome.valid:
                            # Enforce policies (even for cached tokens) if registry present
                            if self._policy_registry and PolicyContext:
                                claims_dict = {}
                                if validation_result.token_data and hasattr(validation_result.token_data, 'claims'):
                                    claims_dict = validation_result.token_data.claims or {}
                                ctx = PolicyContext(
                                    phase=PolicyPhase.VALIDATION,
                                    claims=claims_dict,
                                    request={},
                                    metadata=policy_metadata or {},
                                )
                                try:
                                    self._policy_registry.enforce(ctx)
                                except PolicyViolation:
                                    # Optionally remove token to avoid repeated violations
                                    return None
                            # Metrics: successful validation
                            if increment_counter:
                                try:
                                    increment_counter(METRIC_TOKEN_VALIDATIONS, 1)
                                except Exception:  # pragma: no cover
                                    pass
                            return token_data
                        else:
                            del self._active_tokens[token]
                            return None
                    else:
                        del self._active_tokens[token]
                        return None
                else:
                    del self._active_tokens[token]
                    return None
            
            # Try validating with authenticator even if not in our cache
            validation_result = await self.authenticator.validate_token(token)
            if validation_result and validation_result.valid and validation_result.token_data:
                # Create token data from validation result
                token_data = create_token_data(
                    user_id=validation_result.claims.get('sub', 'unknown'),
                    client_id=validation_result.claims.get('client_id', 'unknown'),
                    scopes=validation_result.claims.get('scope', '').split() if validation_result.claims.get('scope') else [],
                )
                outcome = verify_token_data(
                    validation_result.token_data,
                    expected_audiences=expected_audiences,
                    required_scopes=required_scopes,
                    required_claims=required_claims,
                )
                if outcome.valid:
                    # Post-validation policy enforcement
                    if self._policy_registry and PolicyContext:
                        claims_dict = {}
                        if validation_result.token_data and hasattr(validation_result.token_data, 'claims'):
                            claims_dict = validation_result.token_data.claims or {}
                        ctx = PolicyContext(
                            phase=PolicyPhase.VALIDATION,
                            claims=claims_dict,
                            request={},
                            metadata=policy_metadata or {},
                        )
                        try:
                            self._policy_registry.enforce(ctx)
                        except PolicyViolation:
                            return None
                    self._active_tokens[token] = token_data
                    if increment_counter:
                        try:
                            increment_counter(METRIC_TOKEN_VALIDATIONS, 1)
                        except Exception:  # pragma: no cover
                            pass
                    if set_gauge:
                        try:
                            set_gauge(METRIC_ACTIVE_TOKENS, float(len(self._active_tokens)))
                        except Exception:  # pragma: no cover
                            pass
                    return token_data
                return None
            
            return None
            
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None
    
    async def revoke_token(self, token: str, reason: str = "user_requested") -> bool:
        """
        Revoke an access token.
        
        Args:
            token: Token string to revoke
            reason: Reason for revocation
            
        Returns:
            True if revoked successfully, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Remove from active tokens
            if token in self._active_tokens:
                del self._active_tokens[token]
                if set_gauge:
                    try:
                        set_gauge(METRIC_ACTIVE_TOKENS, float(len(self._active_tokens)))
                    except Exception:  # pragma: no cover
                        pass
            
            # Try to revoke using authenticator
            success = await self.authenticator.revoke_token(token, reason)
            
            if success:
                logger.info(f"Token revoked: {reason}")
            else:
                logger.warning(f"Token revocation failed: {reason}")
            
            return success
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def refresh_token(self, refresh_token: str) -> Optional[TokenResponse]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Refresh token string
            
        Returns:
            New token response if successful, None otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # This would typically validate the refresh token and issue a new access token
            # For now, we'll implement a basic version
            
            # Validate refresh token (simplified)
            validation_result = await self.authenticator.validate_token(refresh_token)
            if not validation_result or not validation_result.valid:
                return None
            
            # Create new token request based on refresh token claims
            token_request = TokenRequest(
                grant_type="refresh_token",
                subject=validation_result.claims.get('sub'),
                scope=validation_result.claims.get('scope', ''),
                audience=validation_result.claims.get('aud'),
            )
            
            # Generate new access token
            return await self.generate_token(token_request)
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None
    
    def get_active_tokens_count(self) -> int:
        """Get the count of active tokens."""
        return len(self._active_tokens)
    
    def get_active_tokens(self) -> List[TokenData]:
        """Get list of active token data."""
        return list(self._active_tokens.values())
    
    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens and return count removed."""
        expired_tokens = []
        
        for token, token_data in self._active_tokens.items():
            if not token_data.is_valid():
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self._active_tokens[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
        
        return len(expired_tokens)
    
    async def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a token.
        
        Args:
            token: Token string
            
        Returns:
            Token information dictionary if found, None otherwise
        """
        token_data = await self.validate_token(token)
        if token_data:
            return token_data.to_dict()
        return None
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            "initialized": self._initialized,
            "auth_type": self.config.auth_type.value,
            "active_tokens": len(self._active_tokens),
            "token_expiry_hours": self.config.access_token_expiry.total_seconds() / 3600,
            "issuer": self.config.issuer,
            "audience": self.config.audience,
        }


def create_auth_service(auth_type: AuthType = AuthType.JWT, **kwargs) -> AuthService:
    """
    Factory function to create an authentication service.
    
    Args:
        auth_type: Type of authentication to use
        **kwargs: Additional configuration options
        
    Returns:
        Configured authentication service
    """
    config = AuthServiceConfig(auth_type=auth_type, **kwargs)
    return AuthService(config)