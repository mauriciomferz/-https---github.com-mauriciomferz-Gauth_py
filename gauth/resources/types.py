"""
Resource types and configuration for GAuth services.
Provides strongly-typed service definitions and configuration management.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional
import time


class ServiceType(str, Enum):
    """Different types of services in the GAuth ecosystem."""
    AUTH = "auth"
    USER = "user"
    ORDER = "order"
    PAYMENT = "payment"
    INVENTORY = "inventory"
    
    def __str__(self) -> str:
        return self.value


class ServiceStatus(str, Enum):
    """Current status of a service."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"
    
    def __str__(self) -> str:
        return self.value


# Service type constants for easier usage
AUTH_SERVICE = ServiceType.AUTH
USER_SERVICE = ServiceType.USER
ORDER_SERVICE = ServiceType.ORDER
PAYMENT_SERVICE = ServiceType.PAYMENT
INVENTORY_SERVICE = ServiceType.INVENTORY

# Status constants
STATUS_HEALTHY = ServiceStatus.HEALTHY
STATUS_DEGRADED = ServiceStatus.DEGRADED
STATUS_UNHEALTHY = ServiceStatus.UNHEALTHY
STATUS_MAINTENANCE = ServiceStatus.MAINTENANCE


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration settings."""
    error_threshold: int = 10
    reset_timeout: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    half_open_calls: int = 5
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'error_threshold': self.error_threshold,
            'reset_timeout': self.reset_timeout.total_seconds(),
            'half_open_calls': self.half_open_calls
        }


@dataclass
class RateLimitConfig:
    """Rate limiting configuration settings."""
    requests_per_second: float = 100.0
    burst_size: int = 20
    window_size: int = 60
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'requests_per_second': self.requests_per_second,
            'burst_size': self.burst_size,
            'window_size': self.window_size
        }


@dataclass
class BulkheadConfig:
    """Resource isolation configuration settings."""
    max_concurrent: int = 10
    queue_size: int = 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'max_concurrent': self.max_concurrent,
            'queue_size': self.queue_size
        }


@dataclass
class RetryConfig:
    """Retry behavior configuration settings."""
    max_attempts: int = 3
    backoff_base: timedelta = field(default_factory=lambda: timedelta(seconds=1))
    max_backoff: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'max_attempts': self.max_attempts,
            'backoff_base': self.backoff_base.total_seconds(),
            'max_backoff': self.max_backoff.total_seconds()
        }


@dataclass
class ServiceConfig:
    """Strongly-typed configuration for services."""
    # Core settings
    type: ServiceType
    name: str
    version: str = "1.0.0"
    dependencies: List[ServiceType] = field(default_factory=list)
    status: ServiceStatus = ServiceStatus.HEALTHY
    
    # Resilience settings
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    bulkhead: BulkheadConfig = field(default_factory=BulkheadConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    
    # Resource limits
    max_concurrency: int = 100
    timeout: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': self.type.value,
            'name': self.name,
            'version': self.version,
            'dependencies': [dep.value for dep in self.dependencies],
            'status': self.status.value,
            'circuit_breaker': self.circuit_breaker.to_dict(),
            'rate_limit': self.rate_limit.to_dict(),
            'bulkhead': self.bulkhead.to_dict(),
            'retry': self.retry.to_dict(),
            'max_concurrency': self.max_concurrency,
            'timeout': self.timeout.total_seconds(),
            'tags': self.tags,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ServiceConfig':
        """Create from dictionary representation."""
        # Convert string enums back to enums
        service_type = ServiceType(data['type'])
        status = ServiceStatus(data['status'])
        dependencies = [ServiceType(dep) for dep in data.get('dependencies', [])]
        
        # Convert configuration objects
        circuit_breaker = CircuitBreakerConfig(
            error_threshold=data['circuit_breaker']['error_threshold'],
            reset_timeout=timedelta(seconds=data['circuit_breaker']['reset_timeout']),
            half_open_calls=data['circuit_breaker']['half_open_calls']
        )
        
        rate_limit = RateLimitConfig(
            requests_per_second=data['rate_limit']['requests_per_second'],
            burst_size=data['rate_limit']['burst_size'],
            window_size=data['rate_limit']['window_size']
        )
        
        bulkhead = BulkheadConfig(
            max_concurrent=data['bulkhead']['max_concurrent'],
            queue_size=data['bulkhead']['queue_size']
        )
        
        retry = RetryConfig(
            max_attempts=data['retry']['max_attempts'],
            backoff_base=timedelta(seconds=data['retry']['backoff_base']),
            max_backoff=timedelta(seconds=data['retry']['max_backoff'])
        )
        
        return cls(
            type=service_type,
            name=data['name'],
            version=data.get('version', '1.0.0'),
            dependencies=dependencies,
            status=status,
            circuit_breaker=circuit_breaker,
            rate_limit=rate_limit,
            bulkhead=bulkhead,
            retry=retry,
            max_concurrency=data.get('max_concurrency', 100),
            timeout=timedelta(seconds=data.get('timeout', 30)),
            tags=data.get('tags', {}),
            created_at=datetime.fromisoformat(data.get('created_at', datetime.now().isoformat())),
            updated_at=datetime.fromisoformat(data.get('updated_at', datetime.now().isoformat()))
        )


@dataclass
class ServiceMetrics:
    """Strongly-typed service metrics."""
    # Request metrics
    total_requests: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    average_latency: timedelta = field(default_factory=lambda: timedelta(0))
    p95_latency: timedelta = field(default_factory=lambda: timedelta(0))
    p99_latency: timedelta = field(default_factory=lambda: timedelta(0))
    
    # Circuit breaker metrics
    circuit_state: str = "closed"
    error_rate: float = 0.0
    last_failure_time: Optional[datetime] = None
    
    # Rate limiting metrics
    current_rate: float = 0.0
    rejected_requests: int = 0
    
    # Resource metrics
    active_requests: int = 0
    queued_requests: int = 0
    resource_usage: float = 0.0
    
    # Metadata
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_requests': self.total_requests,
            'successful_calls': self.successful_calls,
            'failed_calls': self.failed_calls,
            'average_latency': self.average_latency.total_seconds(),
            'p95_latency': self.p95_latency.total_seconds(),
            'p99_latency': self.p99_latency.total_seconds(),
            'circuit_state': self.circuit_state,
            'error_rate': self.error_rate,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'current_rate': self.current_rate,
            'rejected_requests': self.rejected_requests,
            'active_requests': self.active_requests,
            'queued_requests': self.queued_requests,
            'resource_usage': self.resource_usage,
            'last_updated': self.last_updated.isoformat()
        }
    
    def success_rate(self) -> float:
        """Calculate success rate as a percentage."""
        if self.total_requests == 0:
            return 100.0
        return (self.successful_calls / self.total_requests) * 100.0
    
    def is_healthy(self) -> bool:
        """Check if service is healthy based on metrics."""
        if self.total_requests == 0:
            return True
        
        success_rate = self.success_rate()
        return (
            success_rate >= 95.0 and
            self.error_rate < 0.05 and
            self.circuit_state == "closed" and
            self.resource_usage < 0.8
        )
    
    def is_degraded(self) -> bool:
        """Check if service is degraded based on metrics."""
        if self.total_requests == 0:
            return False
        
        success_rate = self.success_rate()
        return (
            85.0 <= success_rate < 95.0 or
            0.05 <= self.error_rate < 0.1 or
            self.circuit_state == "half-open" or
            0.8 <= self.resource_usage < 0.9
        )
    
    def update_latency(self, latency: timedelta) -> None:
        """Update latency metrics with a new measurement."""
        # Simple approximation - in production, use proper percentile tracking
        if self.total_requests == 0:
            self.average_latency = latency
            self.p95_latency = latency
            self.p99_latency = latency
        else:
            # Exponential moving average for simplicity
            alpha = 0.1
            current_ms = latency.total_seconds()
            avg_ms = self.average_latency.total_seconds()
            new_avg_ms = alpha * current_ms + (1 - alpha) * avg_ms
            self.average_latency = timedelta(seconds=new_avg_ms)
            
            # Update percentiles (simplified - actual implementation would need a histogram)
            if current_ms > self.p95_latency.total_seconds():
                self.p95_latency = latency
            if current_ms > self.p99_latency.total_seconds():
                self.p99_latency = latency
        
        self.last_updated = datetime.now()
    
    def record_request(self, success: bool, latency: Optional[timedelta] = None) -> None:
        """Record a request and update metrics."""
        self.total_requests += 1
        
        if success:
            self.successful_calls += 1
        else:
            self.failed_calls += 1
            self.last_failure_time = datetime.now()
        
        if latency:
            self.update_latency(latency)
        
        # Update error rate
        if self.total_requests > 0:
            self.error_rate = self.failed_calls / self.total_requests
        
        self.last_updated = datetime.now()