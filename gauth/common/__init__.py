# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Common package providing shared constants, utilities, and resources for GAuth framework.

This package includes:
- Common messages and error codes
- Utility functions and helpers
- Decorators for common operations
- Constants and defaults used across the framework

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      PARTIALLY USED for grant types and constants
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         PARTIALLY USED for scope constants
"""

from .messages import (
    # Message classes
    ErrorMessages, InfoMessages, ErrorCodes,
    
    # Global instances
    MESSAGES, INFO_MESSAGES, ERROR_CODES,
    
    # Constants
    HTTPStatus, Headers, ContentTypes, Defaults,
    Protocols, GrantTypes, TokenTypes, Scopes, ServiceTypes,
    
    # Response helpers
    get_error_response, get_success_response
)

from .utils import (
    # ID generation
    generate_id, generate_secure_token, generate_request_id, generate_correlation_id,
    
    # Hashing and security
    hash_string, mask_sensitive_data,
    
    # Dictionary operations
    safe_dict_get, safe_list_get, flatten_dict, merge_dicts, 
    sanitize_dict, deep_copy_dict,
    
    # String operations
    truncate_string, normalize_url,
    
    # Time operations
    get_current_timestamp, get_current_iso_timestamp, 
    parse_iso_timestamp, is_expired, format_duration,
    
    # Validation
    validate_required_fields,
    
    # List operations
    chunk_list
)

from .decorators import (
    # Request tracking
    with_request_id,
    
    # Logging and monitoring
    log_execution_time, catch_and_log_exceptions,
    
    # Validation and types
    deprecated, validate_types,
    
    # Performance
    rate_limit, memoize,
    
    # Patterns
    singleton,
    
    # Security
    require_auth
)

__all__ = [
    # Message classes and instances
    'ErrorMessages', 'InfoMessages', 'ErrorCodes',
    'MESSAGES', 'INFO_MESSAGES', 'ERROR_CODES',
    
    # Constants
    'HTTPStatus', 'Headers', 'ContentTypes', 'Defaults',
    'Protocols', 'GrantTypes', 'TokenTypes', 'Scopes', 'ServiceTypes',
    
    # Response helpers
    'get_error_response', 'get_success_response',
    
    # Utility functions
    'generate_id', 'generate_secure_token', 'generate_request_id', 'generate_correlation_id',
    'hash_string', 'mask_sensitive_data',
    'safe_dict_get', 'safe_list_get', 'flatten_dict', 'merge_dicts',
    'sanitize_dict', 'deep_copy_dict',
    'truncate_string', 'normalize_url',
    'get_current_timestamp', 'get_current_iso_timestamp', 
    'parse_iso_timestamp', 'is_expired', 'format_duration',
    'validate_required_fields', 'chunk_list',
    
    # Decorators
    'with_request_id', 'log_execution_time', 'catch_and_log_exceptions',
    'deprecated', 'validate_types', 'rate_limit', 'memoize',
    'singleton', 'require_auth'
]