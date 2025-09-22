# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package resources provides strongly-typed resource definitions and configuration for GAuth protocol (GiFo-RfC 0111).

This package implements resource management and service configuration including:
- Service type definitions and configuration
- Resource limits and constraints
- Service status and health monitoring
- Configuration storage and management

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .types import (
    # Core types
    ServiceType,
    ServiceStatus,
    ServiceConfig,
    ServiceMetrics,
    
    # Configuration types
    CircuitBreakerConfig,
    RateLimitConfig,
    BulkheadConfig,
    RetryConfig,
    
    # Service types
    AUTH_SERVICE,
    USER_SERVICE,
    ORDER_SERVICE,
    PAYMENT_SERVICE,
    INVENTORY_SERVICE,
    
    # Status types
    STATUS_HEALTHY,
    STATUS_DEGRADED,
    STATUS_UNHEALTHY,
    STATUS_MAINTENANCE,
)

from .manager import (
    # Manager classes
    ResourceManager,
    ServiceState,
    ConfigStore,
    MemoryConfigStore,
    
    # Errors
    ServiceNotFoundError,
    ConfigurationError,
    DependencyError,
)

from .store import (
    # Storage implementations
    FileConfigStore,
    DatabaseConfigStore,
)

__all__ = [
    # Core types
    'ServiceType',
    'ServiceStatus',
    'ServiceConfig',
    'ServiceMetrics',
    
    # Configuration types
    'CircuitBreakerConfig',
    'RateLimitConfig', 
    'BulkheadConfig',
    'RetryConfig',
    
    # Constants
    'AUTH_SERVICE',
    'USER_SERVICE',
    'ORDER_SERVICE',
    'PAYMENT_SERVICE',
    'INVENTORY_SERVICE',
    'STATUS_HEALTHY',
    'STATUS_DEGRADED',
    'STATUS_UNHEALTHY',
    'STATUS_MAINTENANCE',
    
    # Management
    'ResourceManager',
    'ServiceState',
    'ConfigStore',
    'MemoryConfigStore',
    'FileConfigStore',
    'DatabaseConfigStore',
    
    # Errors
    'ServiceNotFoundError',
    'ConfigurationError',
    'DependencyError',
]