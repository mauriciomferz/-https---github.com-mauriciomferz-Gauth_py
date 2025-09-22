"""
JWT authentication manager for GAuth.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

try:  # Rotation manager optional import
    from ..token.rotation import RotationManager, RotationPolicy, KeyRecord, KeyStatus
except Exception:  # pragma: no cover
    RotationManager = None  # type: ignore
    RotationPolicy = None  # type: ignore
    KeyRecord = None  # type: ignore
    KeyStatus = None  # type: ignore

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
    
    def __init__(self, config: AuthConfig, rotation_manager: Optional['RotationManager'] = None):
        self.config = config
        self.jwt_config = self._extract_jwt_config()
        self._initialized = False
        self.rotation_manager = rotation_manager  # May be None
    
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

        # Initialize rotation manager if provided
        if self.rotation_manager:
            try:
                await self.rotation_manager.initialize()
            except Exception as e:  # pragma: no cover
                logger.error(f"Failed to initialize rotation manager: {e}")
    
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
            import time
            now_ts = int(time.time())  # authoritative epoch seconds
            # Rotate if needed
            if self.rotation_manager:
                try:
                    await self.rotation_manager.rotate_if_needed()
                except Exception as e:  # pragma: no cover
                    logger.warning(f"Rotation check failed: {e}")
            active_key = None
            kid = None
            secret_key = self.jwt_config.secret_key
            if self.rotation_manager:
                active_key = self.rotation_manager.get_active_key()
                if active_key:
                    kid = active_key.key_id
                    secret_key = active_key.secret.hex()  # derive key material
            exp_ts = now_ts + int(self.jwt_config.expiration_delta.total_seconds())
            logger.debug(f"JWT timing debug now_ts={now_ts} exp_ts={exp_ts}")
            
            # Build claims
            claims = {
                'iss': self.jwt_config.issuer or 'gauth',
                'sub': request.subject or request.username,
                'aud': request.audience or self.jwt_config.audience,
                'exp': exp_ts,
                'iat': now_ts,
                'jti': f"jwt_{now_ts}"
            }
            if kid:
                claims['kid'] = kid
            
            # Add custom claims
            if request.scope:
                claims['scope'] = request.scope
            
            claims.update(request.custom_claims)
            
            # Generate token (mock if PyJWT not available)
            if 'jwt' in globals():
                token = jwt.encode(claims, secret_key, algorithm=self.jwt_config.algorithm)
                if isinstance(token, bytes):
                    token = token.decode('utf-8')
            else:
                # Mock token for testing (embed secret fingerprint length only)
                token = f"mock.jwt.{json.dumps(claims).replace(' ', '')}"
            
            from datetime import datetime, timezone
            issued_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
            return TokenResponse(
                access_token=token,
                token_type="Bearer",
                expires_in=int(self.jwt_config.expiration_delta.total_seconds()),
                scope=request.scope,
                issued_at=issued_dt
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
            kid = None
            if 'jwt' in globals():
                # Real JWT validation
                try:
                    # First decode header to extract kid if present (PyJWT allows options)
                    # PyJWT doesn't expose header-only parse without decode; use get_unverified_header
                    header_kid = None
                    try:
                        header = jwt.get_unverified_header(token)
                        header_kid = header.get('kid')
                    except Exception:  # pragma: no cover
                        header_kid = None

                    # Determine key(s) to attempt
                    secrets_to_try = []
                    if self.rotation_manager and header_kid:
                        rec = self.rotation_manager.get_key(header_kid)
                        if rec and rec.is_usable():
                            secrets_to_try.append(rec.secret.hex())
                    # Fallback: try all usable keys (ACTIVE/GRACE)
                    if self.rotation_manager and not secrets_to_try:
                        active = self.rotation_manager.get_active_key()
                        if active:
                            secrets_to_try.append(active.secret.hex())
                        # Also add any grace keys
                        for rec in await self.rotation_manager.list_keys():
                            if rec.status.name.lower() == 'grace' and rec.is_usable():
                                secrets_to_try.append(rec.secret.hex())
                    if not secrets_to_try:
                        secrets_to_try.append(self.jwt_config.secret_key)

                    payload = None
                    last_error = None
                    for sk in secrets_to_try:
                        try:
                            payload = jwt.decode(
                                token,
                                sk,
                                algorithms=[self.jwt_config.algorithm],
                                audience=self.jwt_config.audience,
                                issuer=self.jwt_config.issuer,
                            )
                            kid = payload.get('kid') or header_kid
                            break
                        except Exception as e:  # keep trying next key
                            last_error = e
                            continue
                    if payload is None:
                        raise last_error or InvalidTokenError("Unable to validate token with available keys")
                    
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
                        kid = claims.get('kid')
                        
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