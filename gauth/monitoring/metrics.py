"""
Metrics collection and management for GAuth protocol monitoring.
Provides comprehensive metrics tracking for authorization, tokens, and system performance.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock
from typing import Dict, List, Optional, Any, Union
import statistics
import time


class MetricType(Enum):
    """Type of metric being tracked."""
    COUNTER = "counter"              # Monotonically increasing metric
    GAUGE = "gauge"                  # Metric that can increase or decrease
    HISTOGRAM = "histogram"          # Distribution of values


# Common metric names
METRIC_AUTH_REQUESTS = "auth_requests_total"
METRIC_TOKENS_ISSUED = "tokens_issued_total"
METRIC_TOKEN_VALIDATIONS = "token_validations_total"
METRIC_TRANSACTIONS = "transactions_total"
METRIC_TRANSACTION_ERRORS = "transaction_errors_total"
METRIC_RATE_LIMIT_HITS = "rate_limit_hits_total"
METRIC_ACTIVE_TOKENS = "active_tokens"
METRIC_AUDIT_EVENTS = "audit_events_total"
METRIC_RESPONSE_TIME = "response_time_seconds"


@dataclass
class Metric:
    """Represents a single monitored metric."""
    name: str
    type: MetricType
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    description: str = ""
    unit: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'type': self.type.value,
            'value': self.value,
            'labels': self.labels,
            'last_updated': self.last_updated.isoformat(),
            'description': self.description,
            'unit': self.unit
        }


@dataclass
class CounterMetric(Metric):
    """Counter metric that only increases."""
    type: MetricType = field(default=MetricType.COUNTER, init=False)
    
    def __post_init__(self):
        if self.value < 0:
            raise ValueError("Counter value cannot be negative")

    def increment(self, amount: float = 1.0) -> None:
        """Increment the counter."""
        if amount < 0:
            raise ValueError("Counter increment cannot be negative")
        self.value += amount
        self.last_updated = datetime.now()


@dataclass
class GaugeMetric(Metric):
    """Gauge metric that can increase or decrease."""
    type: MetricType = field(default=MetricType.GAUGE, init=False)

    def set(self, value: float) -> None:
        """Set the gauge value."""
        self.value = value
        self.last_updated = datetime.now()

    def increment(self, amount: float = 1.0) -> None:
        """Increment the gauge."""
        self.value += amount
        self.last_updated = datetime.now()

    def decrement(self, amount: float = 1.0) -> None:
        """Decrement the gauge."""
        self.value -= amount
        self.last_updated = datetime.now()


@dataclass
class HistogramMetric(Metric):
    """Histogram metric for distributions."""
    type: MetricType = field(default=MetricType.HISTOGRAM, init=False)
    values: List[float] = field(default_factory=list)
    buckets: Dict[float, int] = field(default_factory=dict)
    
    def observe(self, value: float) -> None:
        """Add an observation to the histogram."""
        self.values.append(value)
        self.last_updated = datetime.now()
        
        # Update summary stats
        if self.values:
            self.value = statistics.mean(self.values)

    def percentile(self, p: float) -> float:
        """Calculate percentile."""
        if not self.values:
            return 0.0
        
        sorted_values = sorted(self.values)
        k = (len(sorted_values) - 1) * p / 100
        f = int(k)
        c = k - f
        
        if f + 1 < len(sorted_values):
            return sorted_values[f] * (1 - c) + sorted_values[f + 1] * c
        else:
            return sorted_values[f]

    def summary_stats(self) -> Dict[str, float]:
        """Get summary statistics."""
        if not self.values:
            return {
                'count': 0,
                'sum': 0.0,
                'mean': 0.0,
                'median': 0.0,
                'p95': 0.0,
                'p99': 0.0,
                'min': 0.0,
                'max': 0.0
            }
        
        return {
            'count': len(self.values),
            'sum': sum(self.values),
            'mean': statistics.mean(self.values),
            'median': statistics.median(self.values),
            'p95': self.percentile(95),
            'p99': self.percentile(99),
            'min': min(self.values),
            'max': max(self.values)
        }


class MetricsCollector:
    """Manages system-wide metrics collection."""
    
    def __init__(self):
        self._metrics: Dict[str, Metric] = {}
        self._lock = Lock()

    def register_counter(self, name: str, description: str = "", 
                        labels: Dict[str, str] = None, unit: str = "") -> CounterMetric:
        """Register a new counter metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], CounterMetric):
                    raise ValueError(f"Metric {name} already exists with different type")
                return self._metrics[name]
            
            metric = CounterMetric(
                name=name,
                value=0.0,
                labels=labels or {},
                description=description,
                unit=unit
            )
            self._metrics[name] = metric
            return metric

    def register_gauge(self, name: str, description: str = "",
                      labels: Dict[str, str] = None, unit: str = "") -> GaugeMetric:
        """Register a new gauge metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], GaugeMetric):
                    raise ValueError(f"Metric {name} already exists with different type")
                return self._metrics[name]
            
            metric = GaugeMetric(
                name=name,
                value=0.0,
                labels=labels or {},
                description=description,
                unit=unit
            )
            self._metrics[name] = metric
            return metric

    def register_histogram(self, name: str, description: str = "",
                          labels: Dict[str, str] = None, unit: str = "") -> HistogramMetric:
        """Register a new histogram metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], HistogramMetric):
                    raise ValueError(f"Metric {name} already exists with different type")
                return self._metrics[name]
            
            metric = HistogramMetric(
                name=name,
                value=0.0,
                labels=labels or {},
                description=description,
                unit=unit
            )
            self._metrics[name] = metric
            return metric

    def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name."""
        with self._lock:
            return self._metrics.get(name)

    def get_all_metrics(self) -> Dict[str, Metric]:
        """Get all registered metrics."""
        with self._lock:
            return self._metrics.copy()

    def increment_counter(self, name: str, amount: float = 1.0,
                         labels: Dict[str, str] = None) -> None:
        """Increment a counter metric."""
        metric = self.get_metric(name)
        if not metric:
            metric = self.register_counter(name, labels=labels or {})
        
        if isinstance(metric, CounterMetric):
            metric.increment(amount)
        else:
            raise ValueError(f"Metric {name} is not a counter")

    def set_gauge(self, name: str, value: float,
                 labels: Dict[str, str] = None) -> None:
        """Set a gauge metric value."""
        metric = self.get_metric(name)
        if not metric:
            metric = self.register_gauge(name, labels=labels or {})
        
        if isinstance(metric, GaugeMetric):
            metric.set(value)
        else:
            raise ValueError(f"Metric {name} is not a gauge")

    def observe_histogram(self, name: str, value: float,
                         labels: Dict[str, str] = None) -> None:
        """Add an observation to a histogram metric."""
        metric = self.get_metric(name)
        if not metric:
            metric = self.register_histogram(name, labels=labels or {})
        
        if isinstance(metric, HistogramMetric):
            metric.observe(value)
        else:
            raise ValueError(f"Metric {name} is not a histogram")

    def get_metrics_by_type(self, metric_type: MetricType) -> List[Metric]:
        """Get all metrics of a specific type."""
        with self._lock:
            return [m for m in self._metrics.values() if m.type == metric_type]

    def get_metrics_by_label(self, label_key: str, 
                           label_value: Optional[str] = None) -> List[Metric]:
        """Get metrics that have a specific label."""
        with self._lock:
            if label_value is None:
                return [m for m in self._metrics.values() if label_key in m.labels]
            else:
                return [m for m in self._metrics.values() 
                       if m.labels.get(label_key) == label_value]

    def reset_metric(self, name: str) -> bool:
        """Reset a metric to its initial value."""
        metric = self.get_metric(name)
        if not metric:
            return False
        
        with self._lock:
            if isinstance(metric, CounterMetric):
                metric.value = 0.0
            elif isinstance(metric, GaugeMetric):
                metric.value = 0.0
            elif isinstance(metric, HistogramMetric):
                metric.value = 0.0
                metric.values.clear()
                metric.buckets.clear()
            
            metric.last_updated = datetime.now()
            return True

    def export_metrics(self, format: str = "dict") -> Union[Dict[str, Any], str]:
        """Export metrics in specified format."""
        metrics_data = {}
        
        with self._lock:
            for name, metric in self._metrics.items():
                if isinstance(metric, HistogramMetric):
                    metrics_data[name] = {
                        **metric.to_dict(),
                        'summary_stats': metric.summary_stats()
                    }
                else:
                    metrics_data[name] = metric.to_dict()
        
        if format == "dict":
            return metrics_data
        elif format == "prometheus":
            # Basic Prometheus format
            lines = []
            for name, data in metrics_data.items():
                # Add help line
                if data.get('description'):
                    lines.append(f"# HELP {name} {data['description']}")
                
                # Add type line
                lines.append(f"# TYPE {name} {data['type']}")
                
                # Add metric line
                label_str = ""
                if data.get('labels'):
                    label_pairs = [f'{k}="{v}"' for k, v in data['labels'].items()]
                    label_str = "{" + ",".join(label_pairs) + "}"
                
                lines.append(f"{name}{label_str} {data['value']}")
                lines.append("")
            
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Global metrics collector instance
_global_collector = MetricsCollector()


# Convenience functions for global metrics
def increment_counter(name: str, amount: float = 1.0, 
                     labels: Dict[str, str] = None) -> None:
    """Increment a global counter metric."""
    _global_collector.increment_counter(name, amount, labels)


def set_gauge(name: str, value: float, labels: Dict[str, str] = None) -> None:
    """Set a global gauge metric."""
    _global_collector.set_gauge(name, value, labels)


def observe_histogram(name: str, value: float, 
                     labels: Dict[str, str] = None) -> None:
    """Add observation to a global histogram metric."""
    _global_collector.observe_histogram(name, value, labels)


def get_metric(name: str) -> Optional[Metric]:
    """Get a global metric by name."""
    return _global_collector.get_metric(name)


def get_all_metrics() -> Dict[str, Metric]:
    """Get all global metrics."""
    return _global_collector.get_all_metrics()


def get_global_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    return _global_collector


# Context manager for timing operations
class Timer:
    """Context manager for timing operations."""
    
    def __init__(self, metric_name: str, labels: Dict[str, str] = None):
        self.metric_name = metric_name
        self.labels = labels or {}
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            observe_histogram(self.metric_name, duration, self.labels)