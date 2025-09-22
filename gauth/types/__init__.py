# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package types provides shared type definitions for GAuth protocol (GiFo-RfC 0111).

This package contains common types used across multiple packages to avoid duplication:
- Common enums and constants
- Shared data structures
- Type aliases and utilities

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .common import (
    # Core identifiers
    UserID,
    SessionID,
    TransactionID,
    RequestID,
    
    # Status types
    Status,
    ErrorLevel,
    LogLevel,
    
    # Time utilities
    Timestamp,
    Duration,
    
    # Constants
    DEFAULT_TIMEOUT,
    MAX_RETRY_ATTEMPTS,
    DEFAULT_PAGE_SIZE,
)

from .errors import (
    # Base error types
    GAuthError,
    ValidationError,
    ConfigurationError,
    SecurityError,
    RateLimitError,
    
    # Error codes
    ErrorCode,
    INVALID_REQUEST,
    UNAUTHORIZED,
    FORBIDDEN,
    NOT_FOUND,
    TIMEOUT,
    INTERNAL_ERROR,
)

__all__ = [
    # Core identifiers
    'UserID',
    'SessionID',
    'TransactionID',
    'RequestID',
    
    # Status types
    'Status',
    'ErrorLevel',
    'LogLevel',
    
    # Time utilities
    'Timestamp',
    'Duration',
    
    # Constants
    'DEFAULT_TIMEOUT',
    'MAX_RETRY_ATTEMPTS',
    'DEFAULT_PAGE_SIZE',
    
    # Error types
    'GAuthError',
    'ValidationError',
    'ConfigurationError',
    'SecurityError',
    'RateLimitError',
    'ErrorCode',
    'INVALID_REQUEST',
    'UNAUTHORIZED',
    'FORBIDDEN',
    'NOT_FOUND',
    'TIMEOUT',
    'INTERNAL_ERROR',
]