"""
Performance monitoring functionality for GAuth.
Provides performance metrics, latency tracking, and throughput monitoring.
"""

import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, NamedTuple
from collections import deque, defaultdict
import statistics
import logging

logger = logging.getLogger(__name__)


@dataclass
class RequestLatency:
    """Latency metrics for requests."""
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'min_ms': self.min_ms,
            'max_ms': self.max_ms,
            'avg_ms': self.avg_ms,
            'p50_ms': self.p50_ms,
            'p95_ms': self.p95_ms,
            'p99_ms': self.p99_ms,
            'count': self.count
        }


@dataclass
class ThroughputMetrics:
    """Throughput metrics."""
    requests_per_second: float = 0.0
    total_requests: int = 0
    period_seconds: float = 60.0
    peak_rps: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'requests_per_second': self.requests_per_second,
            'total_requests': self.total_requests,
            'period_seconds': self.period_seconds,
            'peak_rps': self.peak_rps
        }


@dataclass
class ResourceUtilization:
    """Resource utilization metrics."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_mb: float = 0.0
    disk_io_read_mb: float = 0.0
    disk_io_write_mb: float = 0.0
    network_in_mb: float = 0.0
    network_out_mb: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'memory_mb': self.memory_mb,
            'disk_io_read_mb': self.disk_io_read_mb,
            'disk_io_write_mb': self.disk_io_write_mb,
            'network_in_mb': self.network_in_mb,
            'network_out_mb': self.network_out_mb
        }


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics."""
    timestamp: datetime = field(default_factory=datetime.now)
    latency: RequestLatency = field(default_factory=RequestLatency)
    throughput: ThroughputMetrics = field(default_factory=ThroughputMetrics)
    resources: ResourceUtilization = field(default_factory=ResourceUtilization)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'latency': self.latency.to_dict(),
            'throughput': self.throughput.to_dict(),
            'resources': self.resources.to_dict()
        }


class SlidingWindow:
    """Sliding window for time-based metrics."""
    
    def __init__(self, window_size_seconds: float = 60.0, bucket_count: int = 60):
        self.window_size_seconds = window_size_seconds
        self.bucket_count = bucket_count
        self.bucket_duration = window_size_seconds / bucket_count
        self.buckets: deque = deque(maxlen=bucket_count)
        self.current_bucket_start = time.time()
        self.lock = threading.Lock()
        
        # Initialize buckets
        for _ in range(bucket_count):
            self.buckets.append({'count': 0, 'values': []})
    
    def add_value(self, value: float, timestamp: Optional[float] = None) -> None:
        """Add a value to the sliding window."""
        if timestamp is None:
            timestamp = time.time()
        
        with self.lock:
            self._ensure_current_bucket(timestamp)
            self.buckets[-1]['count'] += 1
            self.buckets[-1]['values'].append(value)
    
    def _ensure_current_bucket(self, timestamp: float) -> None:
        """Ensure we have the correct bucket for the timestamp."""
        buckets_to_advance = int((timestamp - self.current_bucket_start) / self.bucket_duration)
        
        if buckets_to_advance > 0:
            # Advance buckets
            for _ in range(min(buckets_to_advance, self.bucket_count)):
                self.buckets.append({'count': 0, 'values': []})
            
            self.current_bucket_start = timestamp
    
    def get_total_count(self) -> int:
        """Get total count across all buckets."""
        with self.lock:
            return sum(bucket['count'] for bucket in self.buckets)
    
    def get_rate_per_second(self) -> float:
        """Get rate per second across the window."""
        total_count = self.get_total_count()
        return total_count / self.window_size_seconds
    
    def get_all_values(self) -> List[float]:
        """Get all values across all buckets."""
        with self.lock:
            values = []
            for bucket in self.buckets:
                values.extend(bucket['values'])
            return values


class LatencyTracker:
    """Tracks latency metrics over time."""
    
    def __init__(self, window_size_seconds: float = 300.0):
        self.window = SlidingWindow(window_size_seconds)
        self.lock = threading.Lock()
    
    def record_latency(self, latency_ms: float) -> None:
        """Record a latency measurement."""
        self.window.add_value(latency_ms)
    
    def get_latency_metrics(self) -> RequestLatency:
        """Get current latency metrics."""
        values = self.window.get_all_values()
        
        if not values:
            return RequestLatency()
        
        sorted_values = sorted(values)
        count = len(sorted_values)
        
        return RequestLatency(
            min_ms=min(sorted_values),
            max_ms=max(sorted_values),
            avg_ms=statistics.mean(sorted_values),
            p50_ms=self._percentile(sorted_values, 50),
            p95_ms=self._percentile(sorted_values, 95),
            p99_ms=self._percentile(sorted_values, 99),
            count=count
        )
    
    def _percentile(self, sorted_values: List[float], percentile: float) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0
        
        index = (percentile / 100.0) * (len(sorted_values) - 1)
        lower_index = int(index)
        upper_index = min(lower_index + 1, len(sorted_values) - 1)
        
        if lower_index == upper_index:
            return sorted_values[lower_index]
        
        weight = index - lower_index
        return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight


class ThroughputTracker:
    """Tracks throughput metrics over time."""
    
    def __init__(self, window_size_seconds: float = 60.0):
        self.window = SlidingWindow(window_size_seconds)
        self.total_requests = 0
        self.peak_rps = 0.0
        self.lock = threading.Lock()
    
    def record_request(self) -> None:
        """Record a request."""
        with self.lock:
            self.window.add_value(1.0)
            self.total_requests += 1
            
            # Update peak RPS
            current_rps = self.window.get_rate_per_second()
            if current_rps > self.peak_rps:
                self.peak_rps = current_rps
    
    def get_throughput_metrics(self) -> ThroughputMetrics:
        """Get current throughput metrics."""
        with self.lock:
            return ThroughputMetrics(
                requests_per_second=self.window.get_rate_per_second(),
                total_requests=self.total_requests,
                period_seconds=self.window.window_size_seconds,
                peak_rps=self.peak_rps
            )


class ResourceMonitor:
    """Monitors system resource utilization."""
    
    def __init__(self):
        self._last_cpu_times = None
        self._last_network_io = None
        self._last_disk_io = None
        self._last_check = time.time()
    
    def get_resource_metrics(self) -> ResourceUtilization:
        """Get current resource utilization metrics."""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_mb = memory.used / (1024 * 1024)
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            disk_read_mb = 0.0
            disk_write_mb = 0.0
            
            if self._last_disk_io and disk_io:
                time_delta = time.time() - self._last_check
                read_delta = disk_io.read_bytes - self._last_disk_io.read_bytes
                write_delta = disk_io.write_bytes - self._last_disk_io.write_bytes
                
                disk_read_mb = (read_delta / (1024 * 1024)) / time_delta
                disk_write_mb = (write_delta / (1024 * 1024)) / time_delta
            
            self._last_disk_io = disk_io
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_in_mb = 0.0
            network_out_mb = 0.0
            
            if self._last_network_io and network_io:
                time_delta = time.time() - self._last_check
                in_delta = network_io.bytes_recv - self._last_network_io.bytes_recv
                out_delta = network_io.bytes_sent - self._last_network_io.bytes_sent
                
                network_in_mb = (in_delta / (1024 * 1024)) / time_delta
                network_out_mb = (out_delta / (1024 * 1024)) / time_delta
            
            self._last_network_io = network_io
            self._last_check = time.time()
            
            return ResourceUtilization(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_mb=memory_mb,
                disk_io_read_mb=disk_read_mb,
                disk_io_write_mb=disk_write_mb,
                network_in_mb=network_in_mb,
                network_out_mb=network_out_mb
            )
            
        except ImportError:
            # Return empty metrics if psutil not available
            return ResourceUtilization()
        except Exception as e:
            logger.warning(f"Failed to get resource metrics: {e}")
            return ResourceUtilization()


class PerformanceMonitor:
    """
    Comprehensive performance monitoring for GAuth operations.
    Tracks latency, throughput, and resource utilization.
    """
    
    def __init__(self, latency_window_seconds: float = 300.0, 
                 throughput_window_seconds: float = 60.0):
        self.latency_tracker = LatencyTracker(latency_window_seconds)
        self.throughput_tracker = ThroughputTracker(throughput_window_seconds)
        self.resource_monitor = ResourceMonitor()
        
        # Operation-specific trackers
        self.operation_latencies: Dict[str, LatencyTracker] = defaultdict(
            lambda: LatencyTracker(latency_window_seconds)
        )
        self.operation_throughputs: Dict[str, ThroughputTracker] = defaultdict(
            lambda: ThroughputTracker(throughput_window_seconds)
        )
    
    def record_operation(self, operation: str, latency_ms: float) -> None:
        """Record an operation with its latency."""
        # Global metrics
        self.latency_tracker.record_latency(latency_ms)
        self.throughput_tracker.record_request()
        
        # Operation-specific metrics
        self.operation_latencies[operation].record_latency(latency_ms)
        self.operation_throughputs[operation].record_request()
    
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get comprehensive performance metrics."""
        return PerformanceMetrics(
            timestamp=datetime.now(),
            latency=self.latency_tracker.get_latency_metrics(),
            throughput=self.throughput_tracker.get_throughput_metrics(),
            resources=self.resource_monitor.get_resource_metrics()
        )
    
    def get_operation_metrics(self, operation: str) -> Dict[str, Any]:
        """Get metrics for a specific operation."""
        latency_metrics = self.operation_latencies[operation].get_latency_metrics()
        throughput_metrics = self.operation_throughputs[operation].get_throughput_metrics()
        
        return {
            'operation': operation,
            'latency': latency_metrics.to_dict(),
            'throughput': throughput_metrics.to_dict()
        }
    
    def get_all_operation_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all tracked operations."""
        metrics = {}
        
        all_operations = set(self.operation_latencies.keys()) | set(self.operation_throughputs.keys())
        
        for operation in all_operations:
            metrics[operation] = self.get_operation_metrics(operation)
        
        return metrics
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all performance metrics."""
        overall_metrics = self.get_performance_metrics()
        operation_metrics = self.get_all_operation_metrics()
        
        return {
            'timestamp': overall_metrics.timestamp.isoformat(),
            'overall': overall_metrics.to_dict(),
            'operations': operation_metrics,
            'operation_count': len(operation_metrics)
        }


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def set_performance_monitor(monitor: PerformanceMonitor) -> None:
    """Set the global performance monitor instance."""
    global _performance_monitor
    _performance_monitor = monitor


def record_operation_latency(operation: str, latency_ms: float) -> None:
    """Record latency for an operation using the global monitor."""
    get_performance_monitor().record_operation(operation, latency_ms)


class PerformanceTimer:
    """Context manager for timing operations."""
    
    def __init__(self, operation: str, monitor: Optional[PerformanceMonitor] = None):
        self.operation = operation
        self.monitor = monitor or get_performance_monitor()
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            latency_ms = (time.time() - self.start_time) * 1000
            self.monitor.record_operation(self.operation, latency_ms)


def time_operation(operation: str):
    """Decorator for timing operations."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with PerformanceTimer(operation):
                return func(*args, **kwargs)
        return wrapper
    return decorator