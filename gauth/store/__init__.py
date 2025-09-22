# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package store provides storage abstractions and implementations for the GAuth protocol (GiFo-RfC 0111).

This package implements comprehensive storage backends including:
- Token storage and metadata management
- Memory-based storage for development/testing
- Redis-based storage for production
- Storage factory and configuration
- Cleanup and maintenance operations

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .types import (
    # Core storage types
    TokenMetadata,
    TokenStore,
    StorageError,
    TokenNotFoundError,
    
    # Storage status
    StorageStatus,
    StorageStats
)

from .memory import (
    # Memory storage implementation
    MemoryTokenStore
)

from .factory import (
    # Storage factory
    create_token_store,
    StorageConfig
)

__all__ = [
    # Core types
    'TokenMetadata',
    'TokenStore', 
    'StorageError',
    'TokenNotFoundError',
    'StorageStatus',
    'StorageStats',
    
    # Implementations
    'MemoryTokenStore',
    
    # Factory
    'create_token_store',
    'StorageConfig'
]