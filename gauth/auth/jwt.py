"""
JWT authentication manager for GAuth.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from .types import (
    AuthConfig, TokenRequest, TokenResponse, TokenData, 
    ValidationResult, Claims
)
from .errors import TokenError, ValidationError, InvalidTokenError

logger = logging.getLogger(__name__)


@dataclass
class JWTConfig:
    """JWT-specific configuration."""
    secret_key: str
    algorithm: str = "HS256"
    issuer: Optional[str] = None
    audience: Optional[str] = None
    expiration_delta: timedelta = timedelta(hours=1)
    
    
class JWTManager:
    """JWT token manager."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.jwt_config = self._extract_jwt_config()
        self._initialized = False
    
    def _extract_jwt_config(self) -> JWTConfig:
        """Extract JWT config from auth config."""
        extra = self.config.extra_config
        
        return JWTConfig(
            secret_key=extra.get('secret_key', 'default-secret-key'),
            algorithm=extra.get('algorithm', 'HS256'),
            issuer=extra.get('issuer'),
            audience=extra.get('audience'),
            expiration_delta=self.config.access_token_expiry
        )
    
    async def initialize(self) -> None:
        """Initialize JWT manager."""
        try:
            # Import JWT library if available
            global jwt
            import jwt
            self._initialized = True
            logger.info("JWT manager initialized")
            
        except ImportError:
            logger.warning("PyJWT not available, using mock implementation")
            self._initialized = True
    
    async def close(self) -> None:
        """Close JWT manager."""
        self._initialized = False
    
    async def validate_credentials(self, credentials: Any) -> bool:
        """Validate credentials (not applicable for JWT)."""
        return True
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate JWT token."""
        if not self._initialized:
            raise TokenError("JWT manager not initialized")
        
        try:
            now = datetime.utcnow()
            exp = now + self.jwt_config.expiration_delta
            
            # Build claims
            claims = {
                'iss': self.jwt_config.issuer or 'gauth',
                'sub': request.subject or request.username,
                'aud': request.audience or self.jwt_config.audience,
                'exp': int(exp.timestamp()),
                'iat': int(now.timestamp()),
                'jti': f"jwt_{int(now.timestamp())}"
            }
            
            # Add custom claims
            if request.scope:
                claims['scope'] = request.scope
            
            claims.update(request.custom_claims)
            
            # Generate token (mock if PyJWT not available)
            if 'jwt' in globals():
                token = jwt.encode(claims, self.jwt_config.secret_key, algorithm=self.jwt_config.algorithm)
                if isinstance(token, bytes):
                    token = token.decode('utf-8')
            else:
                # Mock token for testing
                token = f"mock.jwt.{json.dumps(claims).replace(' ', '')}"
            
            return TokenResponse(
                access_token=token,
                token_type="Bearer",
                expires_in=int(self.jwt_config.expiration_delta.total_seconds()),
                scope=request.scope,
                issued_at=now
            )
            
        except Exception as e:
            logger.error(f"JWT generation failed: {e}")
            raise TokenError(f"JWT generation failed: {str(e)}")
    
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate JWT token."""
        if not self._initialized:
            raise ValidationError("JWT manager not initialized")
        
        try:
            # Validate token (mock if PyJWT not available)
            if 'jwt' in globals():
                # Real JWT validation
                try:
                    payload = jwt.decode(
                        token, 
                        self.jwt_config.secret_key, 
                        algorithms=[self.jwt_config.algorithm],
                        audience=self.jwt_config.audience,
                        issuer=self.jwt_config.issuer
                    )
                    
                    token_data = TokenData(
                        subject=payload.get('sub'),
                        issuer=payload.get('iss'),
                        audience=payload.get('aud'),
                        expires_at=datetime.fromtimestamp(payload['exp']) if 'exp' in payload else None,
                        issued_at=datetime.fromtimestamp(payload['iat']) if 'iat' in payload else None,
                        token_id=payload.get('jti'),
                        scope=payload.get('scope'),
                        claims=payload
                    )
                    
                    return ValidationResult(valid=True, token_data=token_data)
                    
                except jwt.ExpiredSignatureError:
                    return ValidationResult(
                        valid=False,
                        error_message="Token has expired",
                        error_code="EXPIRED_TOKEN"
                    )
                except jwt.InvalidTokenError as e:
                    return ValidationResult(
                        valid=False,
                        error_message=f"Invalid token: {str(e)}",
                        error_code="INVALID_TOKEN"
                    )
            else:
                # Mock validation for testing
                if token.startswith("mock.jwt."):
                    claims_json = token.replace("mock.jwt.", "")
                    try:
                        claims = json.loads(claims_json)
                        
                        token_data = TokenData(
                            subject=claims.get('sub'),
                            issuer=claims.get('iss'),
                            audience=claims.get('aud'),
                            expires_at=datetime.fromtimestamp(claims['exp']) if 'exp' in claims else None,
                            issued_at=datetime.fromtimestamp(claims['iat']) if 'iat' in claims else None,
                            token_id=claims.get('jti'),
                            scope=claims.get('scope'),
                            claims=claims
                        )
                        
                        # Check expiration for mock
                        if token_data.expires_at and datetime.utcnow() > token_data.expires_at:
                            return ValidationResult(
                                valid=False,
                                error_message="Token has expired",
                                error_code="EXPIRED_TOKEN"
                            )
                        
                        return ValidationResult(valid=True, token_data=token_data)
                        
                    except json.JSONDecodeError:
                        return ValidationResult(
                            valid=False,
                            error_message="Invalid mock token format",
                            error_code="INVALID_TOKEN"
                        )
                else:
                    return ValidationResult(
                        valid=False,
                        error_message="Invalid token format",
                        error_code="INVALID_TOKEN"
                    )
            
        except Exception as e:
            logger.error(f"JWT validation failed: {e}")
            return ValidationResult(
                valid=False,
                error_message=f"Validation error: {str(e)}",
                error_code="VALIDATION_ERROR"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke JWT token (stateless, so this is a no-op)."""
        logger.info("JWT revocation requested (stateless tokens cannot be revoked)")
        return True


async def create_jwt_token(config: AuthConfig, request: TokenRequest) -> TokenResponse:
    """Convenience function to create JWT token."""
    manager = JWTManager(config)
    await manager.initialize()
    try:
        return await manager.generate_token(request)
    finally:
        await manager.close()


async def validate_jwt_token(config: AuthConfig, token: str) -> ValidationResult:
    """Convenience function to validate JWT token."""
    manager = JWTManager(config)
    await manager.initialize()
    try:
        return await manager.validate_token(token)
    finally:
        await manager.close()