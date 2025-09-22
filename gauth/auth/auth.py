"""
Core GAuth authenticator implementation.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from .types import (
    AuthConfig, AuthType, Authenticator, TokenRequest, TokenResponse,
    TokenData, ValidationResult, Claims
)
from .errors import (
    AuthError, UnsupportedAuthTypeError, ValidationError, CredentialError
)
from .jwt import JWTManager
from .paseto import PasetoManager
from .oauth2 import OAuth2Manager
from .basic import BasicAuthManager

logger = logging.getLogger(__name__)


class GAuthAuthenticator(Authenticator):
    """
    Main GAuth authenticator that supports multiple authentication types.
    """
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._managers = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the authenticator and its managers."""
        if self._initialized:
            return
        
        try:
            # Initialize the appropriate manager based on auth type
            if self.config.auth_type == AuthType.JWT:
                self._managers['jwt'] = JWTManager(self.config)
                await self._managers['jwt'].initialize()
                
            elif self.config.auth_type == AuthType.PASETO:
                self._managers['paseto'] = PasetoManager(self.config)
                await self._managers['paseto'].initialize()
                
            elif self.config.auth_type == AuthType.OAUTH2:
                self._managers['oauth2'] = OAuth2Manager(self.config)
                await self._managers['oauth2'].initialize()
                
            elif self.config.auth_type == AuthType.BASIC:
                self._managers['basic'] = BasicAuthManager(self.config)
                await self._managers['basic'].initialize()
                
            else:
                raise UnsupportedAuthTypeError(self.config.auth_type.value)
            
            self._initialized = True
            logger.info(f"GAuth authenticator initialized with type: {self.config.auth_type.value}")
            
        except Exception as e:
            logger.error(f"Failed to initialize authenticator: {e}")
            raise AuthError(f"Initialization failed: {str(e)}")
    
    async def close(self) -> None:
        """Close the authenticator and release resources."""
        if not self._initialized:
            return
        
        try:
            for manager in self._managers.values():
                if hasattr(manager, 'close'):
                    await manager.close()
            
            self._managers.clear()
            self._initialized = False
            logger.info("GAuth authenticator closed")
            
        except Exception as e:
            logger.error(f"Error closing authenticator: {e}")
    
    async def validate_credentials(self, credentials: Any) -> bool:
        """Validate credentials using the configured auth type."""
        if not self._initialized:
            raise AuthError("Authenticator not initialized")
        
        try:
            manager = self._get_primary_manager()
            return await manager.validate_credentials(credentials)
            
        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            raise CredentialError(f"Credential validation failed: {str(e)}")
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate a new token."""
        if not self._initialized:
            raise AuthError("Authenticator not initialized")
        
        try:
            manager = self._get_primary_manager()
            response = await manager.generate_token(request)
            
            logger.info(f"Token generated for subject: {request.subject}")
            return response
            
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            raise AuthError(f"Token generation failed: {str(e)}")
    
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate a token."""
        if not self._initialized:
            raise AuthError("Authenticator not initialized")
        
        try:
            manager = self._get_primary_manager()
            result = await manager.validate_token(token)
            
            if result.valid:
                logger.debug("Token validation successful")
            else:
                logger.warning(f"Token validation failed: {result.error_message}")
            
            return result
            
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return ValidationResult(
                valid=False,
                error_message=f"Token validation failed: {str(e)}",
                error_code="VALIDATION_ERROR"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        if not self._initialized:
            raise AuthError("Authenticator not initialized")
        
        try:
            manager = self._get_primary_manager()
            success = await manager.revoke_token(token)
            
            if success:
                logger.info("Token revoked successfully")
            else:
                logger.warning("Token revocation failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    def _get_primary_manager(self):
        """Get the primary manager based on auth type."""
        if self.config.auth_type == AuthType.JWT:
            return self._managers['jwt']
        elif self.config.auth_type == AuthType.PASETO:
            return self._managers['paseto']
        elif self.config.auth_type == AuthType.OAUTH2:
            return self._managers['oauth2']
        elif self.config.auth_type == AuthType.BASIC:
            return self._managers['basic']
        else:
            raise UnsupportedAuthTypeError(self.config.auth_type.value)


class JWTTokenGenerator:
    """JWT token generator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.jwt_manager = JWTManager(config)
    
    async def generate(self, request: TokenRequest) -> TokenResponse:
        """Generate JWT token."""
        return await self.jwt_manager.generate_token(request)


class PasetoTokenGenerator:
    """PASETO token generator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.paseto_manager = PasetoManager(config)
    
    async def generate(self, request: TokenRequest) -> TokenResponse:
        """Generate PASETO token."""
        return await self.paseto_manager.generate_token(request)


class JWTTokenValidator:
    """JWT token validator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.jwt_manager = JWTManager(config)
    
    async def validate(self, token: str) -> ValidationResult:
        """Validate JWT token."""
        return await self.jwt_manager.validate_token(token)


class PasetoTokenValidator:
    """PASETO token validator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.paseto_manager = PasetoManager(config)
    
    async def validate(self, token: str) -> ValidationResult:
        """Validate PASETO token."""
        return await self.paseto_manager.validate_token(token)


class BasicCredentialValidator:
    """Basic credential validator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.basic_manager = BasicAuthManager(config)
    
    async def validate(self, credentials: Dict[str, str]) -> bool:
        """Validate basic credentials."""
        return await self.basic_manager.validate_credentials(credentials)


class OAuth2CredentialValidator:
    """OAuth2 credential validator."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.oauth2_manager = OAuth2Manager(config)
    
    async def validate(self, credentials: Dict[str, str]) -> bool:
        """Validate OAuth2 credentials."""
        return await self.oauth2_manager.validate_credentials(credentials)