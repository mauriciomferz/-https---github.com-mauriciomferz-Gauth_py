"""
Prometheus metrics integration for GAuth.

This module provides Prometheus metrics collection and export functionality
for monitoring authentication, authorization, and system performance.
"""

import time
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timedelta

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, CollectorRegistry, 
        generate_latest, CONTENT_TYPE_LATEST,
        start_http_server, push_to_gateway
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


@dataclass
class MetricConfig:
    """Configuration for metrics collection."""
    
    enabled: bool = True
    prometheus_enabled: bool = True
    push_gateway_url: Optional[str] = None
    push_interval: float = 30.0  # seconds
    job_name: str = "gauth"
    instance_name: str = "default"


class MetricsCollector:
    """Main metrics collector for GAuth operations."""
    
    def __init__(self, config: MetricConfig = None):
        """
        Initialize metrics collector.
        
        Args:
            config: Metrics configuration
        """
        self.config = config or MetricConfig()
        self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        self._metrics_cache: Dict[str, Any] = {}
        
        if not self.config.enabled:
            logger.info("Metrics collection disabled")
            return
        
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available, metrics disabled")
            self.config.prometheus_enabled = False
            return
        
        # Initialize Prometheus metrics
        self._init_prometheus_metrics()
        
        logger.info("Metrics collector initialized")
    
    def _init_prometheus_metrics(self):
        """Initialize all Prometheus metrics."""
        if not PROMETHEUS_AVAILABLE or not self.config.prometheus_enabled:
            return
        
        # Authentication metrics
        self.auth_attempts = Counter(
            'gauth_authentication_attempts_total',
            'Total number of authentication attempts',
            ['method', 'status'],
            registry=self.registry
        )
        
        self.auth_latency = Histogram(
            'gauth_authentication_duration_seconds',
            'Authentication request duration in seconds',
            ['method'],
            buckets=[0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0],
            registry=self.registry
        )
        
        # Token metrics
        self.token_operations = Counter(
            'gauth_token_operations_total',
            'Total number of token operations',
            ['operation', 'type', 'status'],
            registry=self.registry
        )
        
        self.token_validation_errors = Counter(
            'gauth_token_validation_errors_total',
            'Total number of token validation errors',
            ['type', 'error'],
            registry=self.registry
        )
        
        self.active_tokens = Gauge(
            'gauth_active_tokens',
            'Number of currently active tokens',
            ['type'],
            registry=self.registry
        )
        
        # Authorization metrics
        self.authz_decisions = Counter(
            'gauth_authorization_decisions_total',
            'Total number of authorization decisions',
            ['allowed', 'policy'],
            registry=self.registry
        )
        
        self.authz_latency = Histogram(
            'gauth_authorization_duration_seconds',
            'Authorization request duration in seconds',
            ['policy'],
            buckets=[0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1],
            registry=self.registry
        )
        
        self.policy_evaluations = Counter(
            'gauth_policy_evaluations_total',
            'Total number of policy evaluations',
            ['policy', 'result'],
            registry=self.registry
        )
        
        # Cache metrics
        self.cache_operations = Counter(
            'gauth_cache_operations_total',
            'Total number of cache operations',
            ['operation', 'status'],
            registry=self.registry
        )
        
        # Resource metrics
        self.resource_access = Counter(
            'gauth_resource_access_total',
            'Total number of resource access attempts',
            ['resource', 'action', 'allowed'],
            registry=self.registry
        )
        
        # HTTP metrics
        self.http_requests_total = Counter(
            'gauth_http_requests_total',
            'Total number of HTTP requests',
            ['handler', 'method', 'status'],
            registry=self.registry
        )
        
        self.http_request_duration = Histogram(
            'gauth_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['handler', 'method'],
            buckets=[0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0],
            registry=self.registry
        )
        
        self.http_response_size = Histogram(
            'gauth_http_response_size_bytes',
            'HTTP response size in bytes',
            ['handler'],
            buckets=[100, 1000, 10000, 100000, 1000000, 10000000],
            registry=self.registry
        )
        
        self.active_requests = Gauge(
            'gauth_http_active_requests',
            'Number of currently active HTTP requests',
            ['handler'],
            registry=self.registry
        )
        
        # Custom metrics
        self.custom_metrics = Gauge(
            'gauth_custom_metrics',
            'Custom metrics for GAuth resource/service usage',
            ['name'],
            registry=self.registry
        )
    
    # Authentication metrics methods
    async def record_auth_attempt(self, method: str, status: str) -> None:
        """Record an authentication attempt."""
        if not self.config.enabled:
            return
        
        # Update internal cache
        key = f"auth_attempts_{method}_{status}"
        self._metrics_cache[key] = self._metrics_cache.get(key, 0) + 1
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.auth_attempts.labels(method=method, status=status).inc()
        
        logger.debug(f"Recorded auth attempt: {method} -> {status}")
    
    async def observe_auth_latency(self, method: str, duration: float) -> None:
        """Record authentication latency."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.auth_latency.labels(method=method).observe(duration)
        
        logger.debug(f"Recorded auth latency: {method} -> {duration:.4f}s")
    
    # Token metrics methods
    async def record_token_operation(self, operation: str, token_type: str, status: str) -> None:
        """Record a token operation."""
        if not self.config.enabled:
            return
        
        # Update internal cache
        key = f"token_ops_{operation}_{token_type}_{status}"
        self._metrics_cache[key] = self._metrics_cache.get(key, 0) + 1
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.token_operations.labels(
                operation=operation, 
                type=token_type, 
                status=status
            ).inc()
        
        logger.debug(f"Recorded token operation: {operation} {token_type} -> {status}")
    
    async def record_token_validation_error(self, token_type: str, error_type: str) -> None:
        """Record a token validation error."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.token_validation_errors.labels(
                type=token_type, 
                error=error_type
            ).inc()
        
        logger.debug(f"Recorded token validation error: {token_type} -> {error_type}")
    
    async def set_active_tokens(self, token_type: str, count: float) -> None:
        """Set the number of active tokens."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.active_tokens.labels(type=token_type).set(count)
        
        logger.debug(f"Set active tokens: {token_type} -> {count}")
    
    # Authorization metrics methods
    async def record_authz_decision(self, allowed: bool, policy: str) -> None:
        """Record an authorization decision."""
        if not self.config.enabled:
            return
        
        allowed_str = "true" if allowed else "false"
        
        # Update internal cache
        key = f"authz_decisions_{allowed_str}_{policy}"
        self._metrics_cache[key] = self._metrics_cache.get(key, 0) + 1
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.authz_decisions.labels(allowed=allowed_str, policy=policy).inc()
        
        logger.debug(f"Recorded authz decision: {policy} -> {allowed}")
    
    async def observe_authz_latency(self, policy: str, duration: float) -> None:
        """Record authorization latency."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.authz_latency.labels(policy=policy).observe(duration)
        
        logger.debug(f"Recorded authz latency: {policy} -> {duration:.4f}s")
    
    async def record_policy_evaluation(self, policy: str, result: str) -> None:
        """Record a policy evaluation."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.policy_evaluations.labels(policy=policy, result=result).inc()
        
        logger.debug(f"Recorded policy evaluation: {policy} -> {result}")
    
    # Cache metrics methods
    async def record_cache_operation(self, operation: str, status: str) -> None:
        """Record a cache operation."""
        if not self.config.enabled:
            return
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.cache_operations.labels(operation=operation, status=status).inc()
        
        logger.debug(f"Recorded cache operation: {operation} -> {status}")
    
    # Resource metrics methods
    async def record_resource_access(self, resource: str, action: str, allowed: bool) -> None:
        """Record a resource access attempt."""
        if not self.config.enabled:
            return
        
        allowed_str = "true" if allowed else "false"
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.resource_access.labels(
                resource=resource, 
                action=action, 
                allowed=allowed_str
            ).inc()
        
        logger.debug(f"Recorded resource access: {resource}/{action} -> {allowed}")
    
    # HTTP metrics methods
    async def record_http_request(self, handler: str, method: str, status: str, 
                                duration: float, response_size: int) -> None:
        """Record HTTP request metrics."""
        if not self.config.enabled:
            return
        
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.http_requests_total.labels(
                handler=handler, 
                method=method, 
                status=status
            ).inc()
            
            self.http_request_duration.labels(
                handler=handler, 
                method=method
            ).observe(duration)
            
            self.http_response_size.labels(handler=handler).observe(response_size)
        
        logger.debug(f"Recorded HTTP request: {handler} {method} -> {status}")
    
    async def inc_active_requests(self, handler: str) -> None:
        """Increment active requests counter."""
        if not self.config.enabled:
            return
        
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.active_requests.labels(handler=handler).inc()
    
    async def dec_active_requests(self, handler: str) -> None:
        """Decrement active requests counter."""
        if not self.config.enabled:
            return
        
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.active_requests.labels(handler=handler).dec()
    
    # Custom metrics methods
    async def record_value(self, name: str, value: float) -> None:
        """Record a custom metric value."""
        if not self.config.enabled:
            return
        
        # Update internal cache
        self._metrics_cache[f"custom_{name}"] = value
        
        # Update Prometheus metric
        if PROMETHEUS_AVAILABLE and self.config.prometheus_enabled:
            self.custom_metrics.labels(name=name).set(value)
        
        logger.debug(f"Recorded custom metric: {name} -> {value}")
    
    # Generic request tracking
    async def record_request_success(self, service: str) -> None:
        """Record a successful request."""
        await self.record_value(f"{service}_requests_success", 
                               self._metrics_cache.get(f"{service}_requests_success", 0) + 1)
    
    async def record_request_failure(self, service: str) -> None:
        """Record a failed request."""
        await self.record_value(f"{service}_requests_failure", 
                               self._metrics_cache.get(f"{service}_requests_failure", 0) + 1)
    
    # Timer context manager
    @contextmanager
    def timer(self, metric_name: str, labels: Dict[str, str] = None):
        """Context manager for timing operations."""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            
            if metric_name == "auth":
                method = labels.get("method", "unknown") if labels else "unknown"
                asyncio.create_task(self.observe_auth_latency(method, duration))
            elif metric_name == "authz":
                policy = labels.get("policy", "unknown") if labels else "unknown"
                asyncio.create_task(self.observe_authz_latency(policy, duration))
    
    # Export methods
    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        if not PROMETHEUS_AVAILABLE or not self.config.prometheus_enabled:
            return "# Prometheus not available\n"
        
        return generate_latest(self.registry).decode('utf-8')
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of all collected metrics."""
        return {
            "enabled": self.config.enabled,
            "prometheus_enabled": self.config.prometheus_enabled,
            "metrics_count": len(self._metrics_cache),
            "cached_metrics": self._metrics_cache.copy(),
            "timestamp": get_current_time().isoformat()
        }
    
    async def push_to_gateway(self, gateway_url: str = None) -> None:
        """Push metrics to Prometheus push gateway."""
        if not PROMETHEUS_AVAILABLE or not self.config.prometheus_enabled:
            logger.warning("Cannot push metrics: Prometheus not available")
            return
        
        gateway_url = gateway_url or self.config.push_gateway_url
        if not gateway_url:
            logger.warning("No push gateway URL configured")
            return
        
        try:
            push_to_gateway(
                gateway_url,
                job=self.config.job_name,
                registry=self.registry,
                grouping_key={'instance': self.config.instance_name}
            )
            logger.info(f"Metrics pushed to gateway: {gateway_url}")
        except Exception as e:
            logger.error(f"Failed to push metrics to gateway: {e}")


class Timer:
    """Timer for measuring operation duration."""
    
    def __init__(self, collector: MetricsCollector, metric_type: str, labels: Dict[str, str] = None):
        """
        Initialize timer.
        
        Args:
            collector: Metrics collector instance
            metric_type: Type of metric (auth, authz, etc.)
            labels: Additional labels for the metric
        """
        self.collector = collector
        self.metric_type = metric_type
        self.labels = labels or {}
        self.start_time = time.time()
    
    async def stop(self) -> float:
        """Stop the timer and record the duration."""
        duration = time.time() - self.start_time
        
        if self.metric_type == "auth":
            method = self.labels.get("method", "unknown")
            await self.collector.observe_auth_latency(method, duration)
        elif self.metric_type == "authz":
            policy = self.labels.get("policy", "unknown")
            await self.collector.observe_authz_latency(policy, duration)
        
        return duration


def create_metrics_collector(enabled: bool = True,
                           prometheus_enabled: bool = True,
                           push_gateway_url: Optional[str] = None,
                           job_name: str = "gauth",
                           instance_name: str = "default") -> MetricsCollector:
    """
    Create a new metrics collector.
    
    Args:
        enabled: Enable metrics collection
        prometheus_enabled: Enable Prometheus metrics
        push_gateway_url: URL for Prometheus push gateway
        job_name: Job name for metrics
        instance_name: Instance name for metrics
    
    Returns:
        MetricsCollector instance
    """
    config = MetricConfig(
        enabled=enabled,
        prometheus_enabled=prometheus_enabled,
        push_gateway_url=push_gateway_url,
        job_name=job_name,
        instance_name=instance_name
    )
    
    return MetricsCollector(config)


# Global metrics collector instance
_global_collector: Optional[MetricsCollector] = None


def get_global_collector() -> MetricsCollector:
    """Get or create the global metrics collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = create_metrics_collector()
    return _global_collector


def set_global_collector(collector: MetricsCollector) -> None:
    """Set the global metrics collector."""
    global _global_collector
    _global_collector = collector