# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package poa implements Power-of-Attorney (PoA) functionality for the GAuth protocol (GiFo-RfC 115).

This package provides RFC 115 compliant Power-of-Attorney implementation including:
- Authorization types and scopes
- Principal and client management  
- PoA document creation and validation
- Delegation and sub-proxy handling
- Geographic and sector restrictions

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (RFC 111 & RFC 115)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package  
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111 & 0115)
"""

from .types import (
    # Core PoA types
    PowerOfAttorney,
    Principal,
    Client,
    Authorization,
    AuthorizationType,
    RepresentationType,
    SignatureType,
    
    # Geographic and sector definitions
    GeographicRegion,
    IndustrySector,
    
    # Delegation and sub-proxy
    SubProxyRules,
    DelegationLevel,
    
    # Requirements and restrictions
    Requirements,
    Restrictions,
    
    # Status and lifecycle
    PoAStatus,
    ValidationResult
)

from .authorization import (
    # Authorization management
    AuthorizationManager,
    AuthorizationScope,
    TransactionAuthorization,
    DecisionAuthorization,
    ActionAuthorization
)

from .principal import (
    # Principal management
    PrincipalManager,
    PrincipalVerification,
    IdentityVerification
)

from .client import (
    # Client management
    ClientManager,
    ClientRegistration,
    ClientCapabilities
)

from .errors import (
    # PoA specific errors
    PoAError,
    PoAValidationError,
    PoAAuthorizationError,
    PoADelegationError,
    PoAExpirationError
)

__all__ = [
    # Core types
    'PowerOfAttorney',
    'Principal', 
    'Client',
    'Authorization',
    'AuthorizationType',
    'RepresentationType', 
    'SignatureType',
    
    # Geography and sectors
    'GeographicRegion',
    'IndustrySector',
    
    # Delegation
    'SubProxyRules',
    'DelegationLevel',
    
    # Requirements
    'Requirements',
    'Restrictions',
    
    # Status
    'PoAStatus',
    'ValidationResult',
    
    # Managers
    'AuthorizationManager',
    'PrincipalManager',
    'ClientManager',
    
    # Authorization types
    'AuthorizationScope',
    'TransactionAuthorization',
    'DecisionAuthorization',
    'ActionAuthorization',
    
    # Verification
    'PrincipalVerification',
    'IdentityVerification',
    
    # Registration
    'ClientRegistration',
    'ClientCapabilities',
    
    # Errors
    'PoAError',
    'PoAValidationError',
    'PoAAuthorizationError',
    'PoADelegationError',
    'PoAExpirationError'
]