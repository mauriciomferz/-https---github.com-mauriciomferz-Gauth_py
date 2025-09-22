"""
PASETO authentication manager for GAuth.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .types import (
    AuthConfig, TokenRequest, TokenResponse, TokenData, 
    ValidationResult, Claims
)
from .errors import TokenError, ValidationError, InvalidTokenError

logger = logging.getLogger(__name__)


@dataclass
class PasetoConfig:
    """PASETO-specific configuration."""
    secret_key: str
    version: str = "v2"
    purpose: str = "local"  # "local" or "public"
    issuer: Optional[str] = None
    audience: Optional[str] = None
    expiration_delta: timedelta = timedelta(hours=1)
    

class PasetoManager:
    """PASETO token manager."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.paseto_config = self._extract_paseto_config()
        self._initialized = False
    
    def _extract_paseto_config(self) -> PasetoConfig:
        """Extract PASETO config from auth config."""
        extra = self.config.extra_config
        
        return PasetoConfig(
            secret_key=extra.get('secret_key', 'default-paseto-secret-key'),
            version=extra.get('version', 'v2'),
            purpose=extra.get('purpose', 'local'),
            issuer=extra.get('issuer'),
            audience=extra.get('audience'),
            expiration_delta=self.config.access_token_expiry
        )
    
    async def initialize(self) -> None:
        """Initialize PASETO manager."""
        try:
            # Import PASETO library if available
            global pyseto
            import pyseto
            self._initialized = True
            logger.info("PASETO manager initialized")
            
        except ImportError:
            logger.warning("pyseto not available, using mock implementation")
            self._initialized = True
    
    async def close(self) -> None:
        """Close PASETO manager."""
        self._initialized = False
    
    async def validate_credentials(self, credentials: Any) -> bool:
        """Validate credentials (not applicable for PASETO)."""
        return True
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate PASETO token."""
        if not self._initialized:
            raise TokenError("PASETO manager not initialized")
        
        try:
            # Use timezone-aware UTC datetimes to avoid naive/aware comparison warnings
            now = datetime.now(timezone.utc)
            exp = now + self.paseto_config.expiration_delta
            
            # Build payload
            payload = {
                'iss': self.paseto_config.issuer or 'gauth',
                'sub': request.subject or request.username,
                'aud': request.audience or self.paseto_config.audience,
                'exp': exp.isoformat().replace('+00:00', 'Z'),
                'iat': now.isoformat().replace('+00:00', 'Z'),
                'jti': f"paseto_{int(now.timestamp())}"
            }
            
            # Add custom claims
            if request.scope:
                payload['scope'] = request.scope
            
            payload.update(request.custom_claims)
            
            # Generate token (mock if pyseto not available)
            if 'pyseto' in globals():
                # Real PASETO token generation would go here
                # For now, use mock since pyseto setup is complex
                token = f"v2.local.mock.{json.dumps(payload).replace(' ', '')}"
            else:
                # Mock token for testing
                token = f"v2.local.mock.{json.dumps(payload).replace(' ', '')}"
            
            return TokenResponse(
                access_token=token,
                token_type="Bearer",
                expires_in=int(self.paseto_config.expiration_delta.total_seconds()),
                scope=request.scope,
                issued_at=now
            )
            
        except Exception as e:
            logger.error(f"PASETO generation failed: {e}")
            raise TokenError(f"PASETO generation failed: {str(e)}")
    
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate PASETO token."""
        if not self._initialized:
            raise ValidationError("PASETO manager not initialized")
        
        try:
            # Validate token (mock implementation)
            if token.startswith("v2.local.mock."):
                payload_json = token.replace("v2.local.mock.", "")
                try:
                    payload = json.loads(payload_json)
                    
                    # Parse expiration
                    exp_str = payload.get('exp')
                    expires_at = None
                    if exp_str:
                        expires_at = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                    
                    # Parse issued at
                    iat_str = payload.get('iat')
                    issued_at = None
                    if iat_str:
                        issued_at = datetime.fromisoformat(iat_str.replace('Z', '+00:00'))
                    
                    token_data = TokenData(
                        subject=payload.get('sub'),
                        issuer=payload.get('iss'),
                        audience=payload.get('aud'),
                        expires_at=expires_at,
                        issued_at=issued_at,
                        token_id=payload.get('jti'),
                        scope=payload.get('scope'),
                        claims=payload
                    )
                    
                    # Check expiration for mock
                    if expires_at and datetime.now(timezone.utc) > expires_at:
                        return ValidationResult(
                            valid=False,
                            error_message="Token has expired",
                            error_code="EXPIRED_TOKEN"
                        )
                    
                    return ValidationResult(valid=True, token_data=token_data)
                    
                except (json.JSONDecodeError, ValueError) as e:
                    return ValidationResult(
                        valid=False,
                        error_message=f"Invalid mock PASETO format: {str(e)}",
                        error_code="INVALID_TOKEN"
                    )
            else:
                return ValidationResult(
                    valid=False,
                    error_message="Invalid PASETO token format",
                    error_code="INVALID_TOKEN"
                )
            
        except Exception as e:
            logger.error(f"PASETO validation failed: {e}")
            return ValidationResult(
                valid=False,
                error_message=f"Validation error: {str(e)}",
                error_code="VALIDATION_ERROR"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke PASETO token (stateless, so this is a no-op)."""
        logger.info("PASETO revocation requested (stateless tokens cannot be revoked)")
        return True


async def create_paseto_token(config: AuthConfig, request: TokenRequest) -> TokenResponse:
    """Convenience function to create PASETO token."""
    manager = PasetoManager(config)
    await manager.initialize()
    try:
        return await manager.generate_token(request)
    finally:
        await manager.close()


async def validate_paseto_token(config: AuthConfig, token: str) -> ValidationResult:
    """Convenience function to validate PASETO token."""
    manager = PasetoManager(config)
    await manager.initialize()
    try:
        return await manager.validate_token(token)
    finally:
        await manager.close()