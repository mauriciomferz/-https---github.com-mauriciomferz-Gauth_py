"""Optional Prometheus metrics exporter integration.

Provides a small abstraction that conditionally registers Prometheus metrics
if the `prometheus_client` package is installed. Falls back to no-op stubs otherwise.
"""
from __future__ import annotations

from typing import Optional, Dict

try:  # pragma: no cover
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None  # type: ignore


class MetricsRegistry:
    def __init__(self):
        self.enabled = Counter is not None
        if self.enabled:
            self.rate_allowed = Counter("gauth_rate_allowed_total", "Allowed rate limiter decisions", ["algorithm"])  # type: ignore
            self.rate_denied = Counter("gauth_rate_denied_total", "Denied rate limiter decisions", ["algorithm"])  # type: ignore
            self.rate_errors = Counter("gauth_rate_errors_total", "Errors in rate limiter", ["algorithm"])  # type: ignore
        else:
            self.rate_allowed = None
            self.rate_denied = None
            self.rate_errors = None

    def observe_rate(self, metrics: Dict[str, int], algorithm: str):  # pragma: no cover - thin wrapper
        if not self.enabled:
            return
        if metrics.get("allowed"):
            self.rate_allowed.labels(algorithm=algorithm).inc(metrics["allowed"])  # type: ignore
        if metrics.get("denied"):
            self.rate_denied.labels(algorithm=algorithm).inc(metrics["denied"])  # type: ignore
        if metrics.get("errors"):
            self.rate_errors.labels(algorithm=algorithm).inc(metrics["errors"])  # type: ignore


_registry: Optional[MetricsRegistry] = None


def get_registry() -> MetricsRegistry:
    global _registry
    if _registry is None:
        _registry = MetricsRegistry()
    return _registry


__all__ = ["get_registry", "MetricsRegistry"]