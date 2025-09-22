"""
GAuth Metrics Package

Comprehensive metrics collection and export for monitoring GAuth applications.
Includes Prometheus integration, HTTP middleware, and custom metrics tracking.
"""

from .collector import (
    MetricsCollector,
    MetricConfig,
    Timer,
    create_metrics_collector,
    get_global_collector,
    set_global_collector
)

from .exporter import (
    PrometheusExporter,
    MetricsPusher,
    MetricsMiddleware,
    create_prometheus_exporter,
    create_metrics_pusher
)

from .middleware import (
    BaseMetricsMiddleware,
    AioHttpMetricsMiddleware,
    FastAPIMetricsMiddleware,
    FlaskMetricsMiddleware,
    create_aiohttp_middleware,
    create_fastapi_middleware,
    create_flask_middleware,
    metrics_decorator
)


__all__ = [
    # Core metrics collection
    'MetricsCollector',
    'MetricConfig',
    'Timer',
    'create_metrics_collector',
    'get_global_collector',
    'set_global_collector',
    
    # Prometheus export
    'PrometheusExporter',
    'MetricsPusher',
    'MetricsMiddleware',
    'create_prometheus_exporter',
    'create_metrics_pusher',
    
    # HTTP middleware
    'BaseMetricsMiddleware',
    'AioHttpMetricsMiddleware',
    'FastAPIMetricsMiddleware',
    'FlaskMetricsMiddleware',
    'create_aiohttp_middleware',
    'create_fastapi_middleware',
    'create_flask_middleware',
    'metrics_decorator'
]


# Package metadata
__version__ = '1.0.0'
__author__ = 'GAuth Team'
__description__ = 'Comprehensive metrics collection and export for GAuth applications'