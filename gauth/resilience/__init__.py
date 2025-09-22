# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package resilience provides resilience patterns for GAuth protocol (GiFo-RfC 0111).

This package implements various resilience patterns to improve system reliability:
- Retry patterns with exponential backoff
- Timeout management  
- Bulkhead pattern for resource isolation
- Rate limiting and throttling
- Graceful degradation patterns

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .patterns import (
    # Retry patterns
    RetryConfig,
    Retry,
    exponential_backoff,
    linear_backoff,
    fixed_backoff,
    
    # Timeout patterns
    TimeoutConfig,
    Timeout,
    
    # Bulkhead patterns
    BulkheadConfig,
    Bulkhead,
    BulkheadFullError,
    
    # Rate limiting
    RateLimitConfig,
    RateLimiter,
    RateLimitExceededError,
)

from .circuit import (
    # Circuit breaker integration
    CircuitBreakerRetry,
    resilient_call,
)

__all__ = [
    # Retry patterns
    'RetryConfig',
    'Retry',
    'exponential_backoff',
    'linear_backoff',
    'fixed_backoff',
    
    # Timeout patterns
    'TimeoutConfig',
    'Timeout',
    
    # Bulkhead patterns
    'BulkheadConfig',
    'Bulkhead',
    'BulkheadFullError',
    
    # Rate limiting
    'RateLimiter',
    'RateLimitConfig', 
    'RateLimitExceededError',
    
    # Circuit breaker integration
    'CircuitBreakerRetry',
    'resilient_call',
]