"""
Health checking functionality for GAuth monitoring.
Provides health status monitoring for system components.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a system component."""
    name: str
    status: HealthStatus
    last_checked: datetime = field(default_factory=datetime.now)
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'status': self.status.value,
            'last_checked': self.last_checked.isoformat(),
            'message': self.message,
            'details': self.details,
            'duration_ms': self.duration_ms
        }


@dataclass
class SystemHealth:
    """Overall system health status."""
    status: HealthStatus
    components: List[ComponentHealth] = field(default_factory=list)
    check_time: datetime = field(default_factory=datetime.now)
    uptime_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'status': self.status.value,
            'check_time': self.check_time.isoformat(),
            'uptime_seconds': self.uptime_seconds,
            'components': [comp.to_dict() for comp in self.components]
        }


class HealthCheck(ABC):
    """Abstract base class for health checks."""
    
    def __init__(self, name: str, timeout_seconds: float = 5.0):
        self.name = name
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    async def check(self) -> ComponentHealth:
        """Perform the health check."""
        pass


class DatabaseHealthCheck(HealthCheck):
    """Health check for database connectivity."""
    
    def __init__(self, name: str = "database", connection_pool=None):
        super().__init__(name)
        self.connection_pool = connection_pool

    async def check(self) -> ComponentHealth:
        """Check database connectivity."""
        start_time = time.time()
        
        try:
            # Simulate database check
            await asyncio.sleep(0.01)  # Simulate connection check
            
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Database connection successful",
                duration_ms=duration_ms,
                details={"connection_pool_size": 10}  # Mock data
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )


class RedisHealthCheck(HealthCheck):
    """Health check for Redis connectivity."""
    
    def __init__(self, name: str = "redis", redis_client=None):
        super().__init__(name)
        self.redis_client = redis_client

    async def check(self) -> ComponentHealth:
        """Check Redis connectivity."""
        start_time = time.time()
        
        try:
            # Simulate Redis check
            await asyncio.sleep(0.005)  # Simulate ping
            
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Redis connection successful",
                duration_ms=duration_ms,
                details={"memory_usage": "50MB"}  # Mock data
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Redis connection failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )


class ExternalAPIHealthCheck(HealthCheck):
    """Health check for external API dependencies."""
    
    def __init__(self, name: str, api_url: str):
        super().__init__(name)
        self.api_url = api_url

    async def check(self) -> ComponentHealth:
        """Check external API availability."""
        start_time = time.time()
        
        try:
            # Simulate API check
            await asyncio.sleep(0.02)  # Simulate HTTP request
            
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="External API responding",
                duration_ms=duration_ms,
                details={"api_url": self.api_url, "response_code": 200}
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"External API check failed: {str(e)}",
                duration_ms=duration_ms,
                details={"api_url": self.api_url, "error": str(e)}
            )


class MemoryHealthCheck(HealthCheck):
    """Health check for memory usage."""
    
    def __init__(self, name: str = "memory", threshold_percent: float = 85.0):
        super().__init__(name)
        self.threshold_percent = threshold_percent

    async def check(self) -> ComponentHealth:
        """Check memory usage."""
        start_time = time.time()
        
        try:
            import psutil
            
            memory_info = psutil.virtual_memory()
            usage_percent = memory_info.percent
            
            duration_ms = (time.time() - start_time) * 1000
            
            if usage_percent > self.threshold_percent:
                status = HealthStatus.DEGRADED
                message = f"High memory usage: {usage_percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage normal: {usage_percent}%"
            
            return ComponentHealth(
                name=self.name,
                status=status,
                message=message,
                duration_ms=duration_ms,
                details={
                    "usage_percent": usage_percent,
                    "total_gb": round(memory_info.total / (1024**3), 2),
                    "available_gb": round(memory_info.available / (1024**3), 2)
                }
            )
            
        except ImportError:
            # Fallback if psutil not available
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNKNOWN,
                message="Memory monitoring not available (psutil not installed)",
                duration_ms=duration_ms
            )
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Memory check failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )


class HealthChecker:
    """
    Main health checker that coordinates multiple health checks.
    """
    
    def __init__(self):
        self._checks: Dict[str, HealthCheck] = {}
        self._start_time = time.time()

    def add_check(self, check: HealthCheck) -> None:
        """Add a health check."""
        self._checks[check.name] = check
        logger.info(f"Added health check: {check.name}")

    def remove_check(self, name: str) -> bool:
        """Remove a health check."""
        if name in self._checks:
            del self._checks[name]
            logger.info(f"Removed health check: {name}")
            return True
        return False

    async def check_component(self, name: str) -> Optional[ComponentHealth]:
        """Check a specific component."""
        check = self._checks.get(name)
        if not check:
            return None
        
        try:
            return await asyncio.wait_for(
                check.check(),
                timeout=check.timeout_seconds
            )
        except asyncio.TimeoutError:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {check.timeout_seconds}s",
                details={"timeout": True}
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                details={"error": str(e)}
            )

    async def check_all(self) -> SystemHealth:
        """Check all registered components."""
        start_time = time.time()
        component_healths = []
        
        # Run all checks concurrently
        check_tasks = []
        for name in self._checks.keys():
            task = self.check_component(name)
            check_tasks.append(task)
        
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ComponentHealth):
                component_healths.append(result)
            elif isinstance(result, Exception):
                component_healths.append(ComponentHealth(
                    name="unknown",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed with exception: {str(result)}"
                ))
        
        # Determine overall system health
        overall_status = self._calculate_overall_status(component_healths)
        
        return SystemHealth(
            status=overall_status,
            components=component_healths,
            check_time=datetime.now(),
            uptime_seconds=time.time() - self._start_time
        )

    def _calculate_overall_status(self, components: List[ComponentHealth]) -> HealthStatus:
        """Calculate overall system health from component healths."""
        if not components:
            return HealthStatus.UNKNOWN
        
        unhealthy_count = sum(1 for c in components if c.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for c in components if c.status == HealthStatus.DEGRADED)
        
        if unhealthy_count > 0:
            return HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.HEALTHY

    async def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of system health status."""
        system_health = await self.check_all()
        
        component_summary = {}
        for component in system_health.components:
            component_summary[component.name] = {
                'status': component.status.value,
                'message': component.message,
                'duration_ms': component.duration_ms
            }
        
        return {
            'overall_status': system_health.status.value,
            'uptime_seconds': system_health.uptime_seconds,
            'check_time': system_health.check_time.isoformat(),
            'components': component_summary,
            'healthy_components': len([c for c in system_health.components if c.status == HealthStatus.HEALTHY]),
            'total_components': len(system_health.components)
        }


def create_default_health_checker() -> HealthChecker:
    """Create a health checker with default checks."""
    checker = HealthChecker()
    
    # Add basic system checks
    checker.add_check(MemoryHealthCheck())
    
    # These would be added based on actual system dependencies
    # checker.add_check(DatabaseHealthCheck())
    # checker.add_check(RedisHealthCheck())
    
    return checker