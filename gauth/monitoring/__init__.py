# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Package monitoring provides metrics and monitoring capabilities for GAuth protocol (GiFo-RfC 0111).

This package implements comprehensive monitoring and observability including:
- Metrics collection and aggregation
- Performance monitoring
- Audit event tracking
- Health checks and status monitoring
- System resource monitoring

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
"""

from .metrics import (
    # Core metrics
    MetricsCollector,
    Metric,
    MetricType,
    CounterMetric,
    GaugeMetric,
    HistogramMetric,
    Timer,
    
    # Common metric names
    METRIC_AUTH_REQUESTS,
    METRIC_TOKENS_ISSUED,
    METRIC_TOKEN_VALIDATIONS,
    METRIC_TRANSACTIONS,
    METRIC_TRANSACTION_ERRORS,
    METRIC_RATE_LIMIT_HITS,
    METRIC_ACTIVE_TOKENS,
    METRIC_AUDIT_EVENTS,
    METRIC_RESPONSE_TIME,
    
    # Metric operations
    increment_counter,
    set_gauge,
    observe_histogram,
    get_metric,
    get_all_metrics
)

from .health import (
    # Health checking
    HealthChecker,
    HealthStatus,
    HealthCheck,
    ComponentHealth,
    SystemHealth
)

from .performance import (
    # Performance monitoring
    PerformanceMonitor,
    PerformanceMetrics,
    RequestLatency,
    ThroughputMetrics,
    ResourceUtilization
)

__all__ = [
    # Core metrics
    'MetricsCollector',
    'Metric',
    'MetricType',
    'CounterMetric',
    'GaugeMetric', 
    'HistogramMetric',
    'Timer',
    
    # Metric constants
    'METRIC_AUTH_REQUESTS',
    'METRIC_TOKENS_ISSUED',
    'METRIC_TOKEN_VALIDATIONS',
    'METRIC_TRANSACTIONS',
    'METRIC_TRANSACTION_ERRORS',
    'METRIC_RATE_LIMIT_HITS',
    'METRIC_ACTIVE_TOKENS',
    'METRIC_AUDIT_EVENTS',
    'METRIC_RESPONSE_TIME',
    
    # Metric functions
    'increment_counter',
    'set_gauge',
    'observe_histogram',
    'get_metric',
    'get_all_metrics',
    
    # Health monitoring
    'HealthChecker',
    'HealthStatus',
    'HealthCheck',
    'ComponentHealth',
    'SystemHealth',
    
    # Performance monitoring
    'PerformanceMonitor',
    'PerformanceMetrics',
    'RequestLatency',
    'ThroughputMetrics',
    'ResourceUtilization'
]