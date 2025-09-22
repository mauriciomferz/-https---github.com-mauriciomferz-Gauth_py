# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package circuit provides circuit breaker functionality for GAuth protocol (GiFo-RfC 0111).

This package implements the circuit breaker pattern to prevent cascading failures:
- Circuit breaker state management (closed, open, half-open)
- Failure threshold monitoring
- Automatic recovery mechanisms  
- State change callbacks
- Statistics and metrics collection

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .circuit import (
    # Core circuit breaker
    CircuitBreaker,
    CircuitBreakerOptions,
    
    # State management
    CircuitState,
    StateTransition,
    
    # Statistics
    CircuitStats,
    
    # Exceptions
    CircuitBreakerOpenError,
    CircuitBreakerError,
    
    # Decorators and utilities
    circuit_breaker,
    with_circuit_breaker,
)

__all__ = [
    # Core circuit breaker
    'CircuitBreaker',
    'CircuitBreakerOptions',
    
    # State management
    'CircuitState', 
    'StateTransition',
    
    # Statistics
    'CircuitStats',
    
    # Exceptions
    'CircuitBreakerOpenError',
    'CircuitBreakerError',
    
    # Decorators and utilities
    'circuit_breaker',
    'with_circuit_breaker',
]