"""
Basic authentication manager for GAuth.
"""

import base64
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

from .types import (
    AuthConfig, TokenRequest, TokenResponse, TokenData, 
    ValidationResult, Claims
)
from .errors import TokenError, ValidationError, CredentialError

logger = logging.getLogger(__name__)


@dataclass
class BasicAuthConfig:
    """Basic authentication configuration."""
    users: Dict[str, str] = None  # username -> password_hash
    realm: str = "GAuth"
    hash_algorithm: str = "sha256"
    

class BasicAuthManager:
    """Basic authentication manager."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.basic_config = self._extract_basic_config()
        self._initialized = False
    
    def _extract_basic_config(self) -> BasicAuthConfig:
        """Extract basic auth config from auth config."""
        extra = self.config.extra_config
        
        # Default test users
        default_users = {
            'admin': self._hash_password('admin123'),
            'user': self._hash_password('user123')
        }
        
        return BasicAuthConfig(
            users=extra.get('users', default_users),
            realm=extra.get('realm', 'GAuth'),
            hash_algorithm=extra.get('hash_algorithm', 'sha256')
        )
    
    def _hash_password(self, password: str) -> str:
        """Hash password using configured algorithm."""
        if self.basic_config and self.basic_config.hash_algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            return hashlib.sha256(password.encode()).hexdigest()
    
    async def initialize(self) -> None:
        """Initialize basic auth manager."""
        self._initialized = True
        logger.info("Basic auth manager initialized")
    
    async def close(self) -> None:
        """Close basic auth manager."""
        self._initialized = False
    
    async def validate_credentials(self, credentials: Any) -> bool:
        """Validate basic authentication credentials."""
        if not self._initialized:
            raise CredentialError("Basic auth manager not initialized")
        
        try:
            if isinstance(credentials, dict):
                username = credentials.get('username')
                password = credentials.get('password')
            elif isinstance(credentials, str):
                # Parse Authorization header: "Basic base64(username:password)"
                if credentials.startswith('Basic '):
                    encoded = credentials[6:]  # Remove "Basic "
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    username, password = decoded.split(':', 1)
                else:
                    return False
            else:
                return False
            
            if not username or not password:
                return False
            
            # Check against configured users
            if username in self.basic_config.users:
                expected_hash = self.basic_config.users[username]
                password_hash = self._hash_password(password)
                return password_hash == expected_hash
            
            return False
            
        except Exception as e:
            logger.error(f"Basic auth validation failed: {e}")
            return False
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate token after basic auth validation."""
        if not self._initialized:
            raise TokenError("Basic auth manager not initialized")
        
        try:
            # For basic auth, we generate a simple session token
            now = datetime.utcnow()
            expires_in = int(self.config.access_token_expiry.total_seconds())
            
            # Create a basic token (in practice, you might use JWT or similar)
            token_data = {
                'username': request.username,
                'issued_at': now.isoformat(),
                'expires_at': (now + self.config.access_token_expiry).isoformat()
            }
            
            # Simple token format for basic auth
            token_str = base64.b64encode(str(token_data).encode()).decode()
            token = f"basic_{token_str}"
            
            return TokenResponse(
                access_token=token,
                token_type="Bearer",
                expires_in=expires_in,
                scope=request.scope,
                issued_at=now
            )
            
        except Exception as e:
            logger.error(f"Basic auth token generation failed: {e}")
            raise TokenError(f"Basic auth token generation failed: {str(e)}")
    
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate basic auth token."""
        if not self._initialized:
            raise ValidationError("Basic auth manager not initialized")
        
        try:
            if not token.startswith("basic_"):
                return ValidationResult(
                    valid=False,
                    error_message="Invalid basic auth token format",
                    error_code="INVALID_TOKEN"
                )
            
            # Extract token data
            token_str = token[6:]  # Remove "basic_" prefix
            try:
                decoded = base64.b64decode(token_str).decode()
                # This is a simplified parsing - in practice use proper JSON
                # For now, just validate the format
                if 'username' in decoded and 'issued_at' in decoded:
                    # Extract username (simplified)
                    start = decoded.find("'username': '") + 13
                    end = decoded.find("'", start)
                    username = decoded[start:end] if start < end else "unknown"
                    
                    now = datetime.utcnow()
                    token_data = TokenData(
                        subject=username,
                        issuer="basic_auth",
                        expires_at=now + timedelta(hours=1),  # Simplified
                        issued_at=now,
                        token_id=token,
                        claims={'auth_type': 'basic', 'username': username}
                    )
                    
                    return ValidationResult(valid=True, token_data=token_data)
                else:
                    return ValidationResult(
                        valid=False,
                        error_message="Invalid token data",
                        error_code="INVALID_TOKEN"
                    )
                    
            except Exception as e:
                return ValidationResult(
                    valid=False,
                    error_message=f"Token parsing failed: {str(e)}",
                    error_code="INVALID_TOKEN"
                )
            
        except Exception as e:
            logger.error(f"Basic auth validation failed: {e}")
            return ValidationResult(
                valid=False,
                error_message=f"Validation error: {str(e)}",
                error_code="VALIDATION_ERROR"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke basic auth token."""
        if not self._initialized:
            return False
        
        # For basic auth, we could maintain a blacklist
        # For now, just log the revocation
        logger.info(f"Basic auth token revocation requested: {token[:20]}...")
        return True
    
    def get_auth_header(self, username: str, password: str) -> str:
        """Generate Authorization header for basic auth."""
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"


async def validate_basic_credentials(config: AuthConfig, username: str, password: str) -> bool:
    """Convenience function to validate basic credentials."""
    manager = BasicAuthManager(config)
    await manager.initialize()
    try:
        credentials = {'username': username, 'password': password}
        return await manager.validate_credentials(credentials)
    finally:
        await manager.close()