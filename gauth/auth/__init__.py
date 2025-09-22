# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package auth provides authentication and authorization functionality for GAuth protocol (GiFo-RfC 0111).

This package implements core authentication mechanisms including:
- JWT token authentication and validation
- PASETO token authentication  
- OAuth2 authentication flows
- Basic authentication
- Token generation and validation
- Credential validation

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      USED for OAuth2 flows only (see [OAuth2] comments) 
  - PKCE:           SUPPORTED in OAuth2 flows (see [PKCE] comments)
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
[OAuth2] = OAuth 2.0 protocol logic (RFC 6749)
[PKCE] = PKCE extension logic (RFC 7636)
"""

from .types import (
    # Authentication types
    AuthType,
    AuthConfig,
    TokenValidationConfig,
    Authenticator,
    
    # Request/Response types
    TokenRequest,
    TokenResponse,
    TokenData,
    Metadata,
    Claims,
    
    # Validation types
    ApprovalRule,
    ValidationResult,
)

from .auth import (
    # Core authenticator implementation
    GAuthAuthenticator,
    
    # Token generators
    JWTTokenGenerator,
    PasetoTokenGenerator,
    
    # Token validators
    JWTTokenValidator,
    PasetoTokenValidator,
    
    # Credential validators
    BasicCredentialValidator,
    OAuth2CredentialValidator,
)

from .jwt import (
    # JWT functionality
    JWTManager,
    JWTConfig,
    create_jwt_token,
    validate_jwt_token,
)

from .paseto import (
    # PASETO functionality 
    PasetoManager,
    PasetoConfig,
    create_paseto_token,
    validate_paseto_token,
)

from .oauth2 import (
    # OAuth2 functionality
    OAuth2Manager,
    OAuth2Config,
    OAuth2Flow,
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
)

from .basic import (
    # Basic authentication
    BasicAuthManager,
    BasicAuthConfig,
    validate_basic_credentials,
)

from .service import (
    # Authentication service
    AuthService,
    AuthServiceConfig,
    create_auth_service,
)

from .errors import (
    # Authentication errors
    AuthError,
    TokenError,
    ValidationError,
    CredentialError,
    ExpiredTokenError,
    InvalidTokenError,
    UnsupportedAuthTypeError,
)

__all__ = [
    # Core types
    'AuthType',
    'AuthConfig', 
    'TokenValidationConfig',
    'Authenticator',
    'TokenRequest',
    'TokenResponse',
    'TokenData',
    'Metadata',
    'Claims',
    'ApprovalRule',
    'ValidationResult',
    
    # Core implementation
    'GAuthAuthenticator',
    'JWTTokenGenerator',
    'PasetoTokenGenerator',
    'JWTTokenValidator',
    'PasetoTokenValidator',
    'BasicCredentialValidator',
    'OAuth2CredentialValidator',
    
    # JWT
    'JWTManager',
    'JWTConfig',
    'create_jwt_token',
    'validate_jwt_token',
    
    # PASETO
    'PasetoManager',
    'PasetoConfig',
    'create_paseto_token',
    'validate_paseto_token',
    
    # OAuth2
    'OAuth2Manager',
    'OAuth2Config',
    'OAuth2Flow',
    'AuthorizationCodeFlow',
    'ClientCredentialsFlow',
    
    # Basic auth
    'BasicAuthManager',
    'BasicAuthConfig',
    'validate_basic_credentials',
    
    # Authentication service
    'AuthService',
    'AuthServiceConfig',
    'create_auth_service',
    
    # Errors
    'AuthError',
    'TokenError',
    'ValidationError',
    'CredentialError',
    'ExpiredTokenError',
    'InvalidTokenError',
    'UnsupportedAuthTypeError',
]