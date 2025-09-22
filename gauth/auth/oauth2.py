"""
OAuth2 authentication manager for GAuth.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List
from urllib.parse import urlencode, parse_qs

from .types import (
    AuthConfig, TokenRequest, TokenResponse, TokenData, 
    ValidationResult, Claims
)
from .errors import TokenError, ValidationError, CredentialError

logger = logging.getLogger(__name__)


@dataclass
class OAuth2Config:
    """OAuth2-specific configuration."""
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None
    scopes: List[str] = None
    response_type: str = "code"
    grant_type: str = "authorization_code"
    

class OAuth2Flow(ABC):
    """Abstract OAuth2 flow."""
    
    @abstractmethod
    async def get_authorization_url(self, state: Optional[str] = None) -> str:
        """Get authorization URL."""
        pass
    
    @abstractmethod
    async def exchange_code(self, code: str, state: Optional[str] = None) -> TokenResponse:
        """Exchange authorization code for token."""
        pass


class AuthorizationCodeFlow(OAuth2Flow):
    """OAuth2 Authorization Code flow."""
    
    def __init__(self, config: OAuth2Config):
        self.config = config
    
    async def get_authorization_url(self, state: Optional[str] = None) -> str:
        """Get authorization URL for the user to visit."""
        params = {
            'response_type': self.config.response_type,
            'client_id': self.config.client_id,
            'scope': ' '.join(self.config.scopes or []),
            'state': state or 'default_state'
        }
        
        if self.config.redirect_uri:
            params['redirect_uri'] = self.config.redirect_uri
        
        return f"{self.config.authorization_endpoint}?{urlencode(params)}"
    
    async def exchange_code(self, code: str, state: Optional[str] = None) -> TokenResponse:
        """Exchange authorization code for access token."""
        # Mock implementation - real implementation would make HTTP request
        logger.info(f"Exchanging authorization code: {code}")
        
        now = datetime.utcnow()
        expires_in = 3600  # 1 hour
        
        return TokenResponse(
            access_token=f"oauth2_access_token_{code}",
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=f"oauth2_refresh_token_{code}",
            scope=' '.join(self.config.scopes or []),
            issued_at=now
        )


class ClientCredentialsFlow(OAuth2Flow):
    """OAuth2 Client Credentials flow."""
    
    def __init__(self, config: OAuth2Config):
        self.config = config
    
    async def get_authorization_url(self, state: Optional[str] = None) -> str:
        """Not applicable for client credentials flow."""
        raise NotImplementedError("Client credentials flow does not use authorization URL")
    
    async def exchange_code(self, code: str, state: Optional[str] = None) -> TokenResponse:
        """Not applicable for client credentials flow."""
        raise NotImplementedError("Client credentials flow does not use authorization code")
    
    async def get_token(self) -> TokenResponse:
        """Get token using client credentials."""
        # Mock implementation - real implementation would make HTTP request
        logger.info("Getting token using client credentials")
        
        now = datetime.utcnow()
        expires_in = 3600  # 1 hour
        
        return TokenResponse(
            access_token=f"oauth2_client_token_{self.config.client_id}",
            token_type="Bearer",
            expires_in=expires_in,
            scope=' '.join(self.config.scopes or []),
            issued_at=now
        )


class OAuth2Manager:
    """OAuth2 manager."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.oauth2_config = self._extract_oauth2_config()
        self._flows = {}
        self._initialized = False
    
    def _extract_oauth2_config(self) -> OAuth2Config:
        """Extract OAuth2 config from auth config."""
        extra = self.config.extra_config
        
        return OAuth2Config(
            authorization_endpoint=extra.get('authorization_endpoint', 'https://auth.example.com/oauth/authorize'),
            token_endpoint=extra.get('token_endpoint', 'https://auth.example.com/oauth/token'),
            client_id=self.config.client_id or 'default_client_id',
            client_secret=self.config.client_secret or 'default_client_secret',
            redirect_uri=extra.get('redirect_uri'),
            scopes=self.config.scopes,
            response_type=extra.get('response_type', 'code'),
            grant_type=extra.get('grant_type', 'authorization_code')
        )
    
    async def initialize(self) -> None:
        """Initialize OAuth2 manager."""
        self._flows['authorization_code'] = AuthorizationCodeFlow(self.oauth2_config)
        self._flows['client_credentials'] = ClientCredentialsFlow(self.oauth2_config)
        self._initialized = True
        logger.info("OAuth2 manager initialized")
    
    async def close(self) -> None:
        """Close OAuth2 manager."""
        self._flows.clear()
        self._initialized = False
    
    async def validate_credentials(self, credentials: Dict[str, str]) -> bool:
        """Validate OAuth2 credentials."""
        if not self._initialized:
            raise CredentialError("OAuth2 manager not initialized")
        
        # Basic validation of client credentials
        client_id = credentials.get('client_id')
        client_secret = credentials.get('client_secret')
        
        if not client_id or not client_secret:
            return False
        
        # Mock validation - real implementation would verify against OAuth2 server
        return (client_id == self.oauth2_config.client_id and 
                client_secret == self.oauth2_config.client_secret)
    
    async def generate_token(self, request: TokenRequest) -> TokenResponse:
        """Generate OAuth2 token."""
        if not self._initialized:
            raise TokenError("OAuth2 manager not initialized")
        
        try:
            if request.grant_type == "authorization_code":
                flow = self._flows['authorization_code']
                code = request.custom_claims.get('code')
                if not code:
                    raise TokenError("Authorization code required")
                return await flow.exchange_code(code)
                
            elif request.grant_type == "client_credentials":
                flow = self._flows['client_credentials']
                return await flow.get_token()
                
            else:
                raise TokenError(f"Unsupported grant type: {request.grant_type}")
                
        except Exception as e:
            logger.error(f"OAuth2 token generation failed: {e}")
            raise TokenError(f"OAuth2 token generation failed: {str(e)}")
    
    async def validate_token(self, token: str) -> ValidationResult:
        """Validate OAuth2 token."""
        if not self._initialized:
            raise ValidationError("OAuth2 manager not initialized")
        
        try:
            # Mock validation - real implementation would verify with OAuth2 server
            if token.startswith("oauth2_"):
                # Extract token info (mock)
                parts = token.split("_")
                if len(parts) >= 3:
                    token_type = parts[1]  # access or refresh
                    identifier = "_".join(parts[2:])
                    
                    now = datetime.utcnow()
                    token_data = TokenData(
                        subject=identifier,
                        issuer="oauth2_server",
                        audience=self.oauth2_config.client_id,
                        expires_at=now + timedelta(hours=1),
                        issued_at=now,
                        token_id=token,
                        scope=' '.join(self.oauth2_config.scopes or []),
                        claims={
                            'token_type': token_type,
                            'client_id': self.oauth2_config.client_id
                        }
                    )
                    
                    return ValidationResult(valid=True, token_data=token_data)
            
            return ValidationResult(
                valid=False,
                error_message="Invalid OAuth2 token format",
                error_code="INVALID_TOKEN"
            )
            
        except Exception as e:
            logger.error(f"OAuth2 validation failed: {e}")
            return ValidationResult(
                valid=False,
                error_message=f"Validation error: {str(e)}",
                error_code="VALIDATION_ERROR"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke OAuth2 token."""
        if not self._initialized:
            return False
        
        # Mock revocation - real implementation would call OAuth2 server
        logger.info(f"OAuth2 token revocation requested: {token[:20]}...")
        return True
    
    def get_flow(self, flow_type: str) -> OAuth2Flow:
        """Get OAuth2 flow by type."""
        if flow_type not in self._flows:
            raise ValueError(f"Unsupported OAuth2 flow: {flow_type}")
        return self._flows[flow_type]