# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package authz implements authorization policies and decisions for the GAuth protocol (GiFo-RfC 0111).

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this file (see [GAuth] comments below)
  - OAuth 2.0:      NOT USED anywhere in this file
  - PKCE:           NOT USED anywhere in this file
  - OpenID:         NOT USED anywhere in this file

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
[Other] = Placeholder for OAuth2, OpenID, PKCE, or other protocols (none present in this file)
"""

from .types import (
    Subject,
    Resource, 
    Action,
    Policy,
    AccessRequest,
    AccessResponse,
    Decision,
    Effect,
    Condition,
    Allow,
    Deny
)

from .authz import (
    Authorizer,
    MemoryAuthorizer,
    PolicyEngine,
    PolicyStore
)

from .conditions import (
    TimeCondition,
    IPCondition,
    RoleCondition,
    AttributeCondition
)

from .context import (
    AuthorizationContext,
    RequestContext
)

__all__ = [
    # Types
    'Subject',
    'Resource', 
    'Action',
    'Policy',
    'AccessRequest',
    'AccessResponse',
    'Decision',
    'Effect',
    'Condition',
    'Allow',
    'Deny',
    
    # Core authorization
    'Authorizer',
    'MemoryAuthorizer',
    'PolicyEngine',
    'PolicyStore',
    
    # Conditions
    'TimeCondition',
    'IPCondition',
    'RoleCondition',
    'AttributeCondition',
    
    # Context
    'AuthorizationContext',
    'RequestContext'
]