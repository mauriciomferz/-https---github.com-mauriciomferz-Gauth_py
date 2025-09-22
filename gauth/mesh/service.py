"""
Service mesh service management module.

This module provides service coordination and interaction management
within the GAuth service mesh, including resilience patterns and
event-driven communication.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import time

from ..events.bus import EventBus, Event, EventType, Metadata
from ..resources.types import ServiceType, ServiceConfig, ServiceMetrics
from ..common.utils import get_current_time, generate_id


logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Mesh-wide configuration."""
    
    name: str
    metrics_enabled: bool = True
    tracing_enabled: bool = True
    default_timeout: float = 30.0  # seconds


class Service:
    """Service in the mesh with resilience patterns."""
    
    def __init__(self, config: ServiceConfig, mesh: 'ServiceMesh'):
        self.config = config
        self.mesh = mesh
        self.metrics = ServiceMetrics()
        self.event_bus = mesh.event_bus
        self._lock = asyncio.Lock()
    
    async def process(self, action: Callable[[], Any]) -> Any:
        """Execute a request with configured resilience patterns."""
        start_time = time.time()
        
        try:
            # Execute the action
            if asyncio.iscoroutinefunction(action):
                result = await action()
            else:
                result = action()
            
            # Record successful metrics
            async with self._lock:
                self.metrics.total_requests += 1
                self.metrics.successful_calls += 1
                self._update_latency_metrics(time.time() - start_time)
            
            # Publish success event
            await self._publish_event("success", {
                "duration": time.time() - start_time,
                "service": self.config.name
            })
            
            return result
            
        except Exception as e:
            # Record failure metrics
            async with self._lock:
                self.metrics.total_requests += 1
                self.metrics.failed_calls += 1
                self.metrics.last_failure_time = get_current_time()
            
            # Publish failure event
            await self._publish_event("failure", {
                "duration": time.time() - start_time,
                "service": self.config.name,
                "error": str(e)
            })
            
            logger.error(f"Service {self.config.name} operation failed: {e}")
            raise
    
    async def on_event(self, handler: Callable[[Event], Any]) -> None:
        """Subscribe to events for this service."""
        await self.event_bus.subscribe(handler)
    
    async def get_metrics(self) -> ServiceMetrics:
        """Get current service metrics."""
        async with self._lock:
            return ServiceMetrics(
                total_requests=self.metrics.total_requests,
                successful_calls=self.metrics.successful_calls,
                failed_calls=self.metrics.failed_calls,
                average_latency=self.metrics.average_latency,
                last_failure_time=self.metrics.last_failure_time
            )
    
    def _update_latency_metrics(self, duration: float) -> None:
        """Update latency metrics with new duration."""
        if self.metrics.successful_calls == 1:
            self.metrics.average_latency = duration
        else:
            # Calculate running average
            total_time = self.metrics.average_latency * (self.metrics.successful_calls - 1)
            self.metrics.average_latency = (total_time + duration) / self.metrics.successful_calls
    
    async def _publish_event(self, event_type: str, metadata: Dict[str, Any]) -> None:
        """Publish an event to the event bus."""
        try:
            event_metadata = Metadata()
            for key, value in metadata.items():
                event_metadata.set_string(key, str(value))
            
            event = Event(
                id=generate_id(),
                type=EventType.SYSTEM,
                timestamp=get_current_time(),
                resource=self.config.name,
                metadata=event_metadata,
                error=metadata.get("error")
            )
            
            await self.event_bus.publish(event)
            
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")


class ServiceMesh:
    """Service mesh coordinator."""
    
    def __init__(self, config: Config):
        self.config = config
        self.services: Dict[ServiceType, Service] = {}
        self.event_bus = EventBus()
        self._lock = asyncio.Lock()
        self._running = False
    
    async def start(self) -> None:
        """Start the service mesh."""
        if self._running:
            logger.warning("Service mesh is already running")
            return
        
        try:
            # Start event bus
            await self.event_bus.start()
            
            self._running = True
            logger.info(f"Service mesh '{self.config.name}' started")
            
        except Exception as e:
            logger.error(f"Failed to start service mesh: {e}")
            raise
    
    async def stop(self) -> None:
        """Stop the service mesh."""
        if not self._running:
            return
        
        try:
            # Stop event bus
            await self.event_bus.stop()
            
            # Clear services
            async with self._lock:
                self.services.clear()
            
            self._running = False
            logger.info(f"Service mesh '{self.config.name}' stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop service mesh: {e}")
            raise
    
    async def add_service(self, config: ServiceConfig) -> Service:
        """Add a new service to the mesh."""
        async with self._lock:
            if config.type in self.services:
                logger.warning(f"Service {config.type} already exists, replacing")
            
            service = Service(config, self)
            self.services[config.type] = service
            
            logger.info(f"Added service {config.name} ({config.type}) to mesh")
            return service
    
    async def remove_service(self, service_type: ServiceType) -> None:
        """Remove a service from the mesh."""
        async with self._lock:
            if service_type in self.services:
                del self.services[service_type]
                logger.info(f"Removed service {service_type} from mesh")
            else:
                logger.warning(f"Service {service_type} not found in mesh")
    
    async def get_service(self, service_type: ServiceType) -> Optional[Service]:
        """Get a service by type."""
        async with self._lock:
            return self.services.get(service_type)
    
    async def list_services(self) -> List[Service]:
        """List all services in the mesh."""
        async with self._lock:
            return list(self.services.values())
    
    async def get_mesh_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics for the entire mesh."""
        async with self._lock:
            total_requests = 0
            total_successes = 0
            total_failures = 0
            service_count = len(self.services)
            
            for service in self.services.values():
                metrics = await service.get_metrics()
                total_requests += metrics.total_requests
                total_successes += metrics.successful_calls
                total_failures += metrics.failed_calls
            
            success_rate = (total_successes / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "mesh_name": self.config.name,
                "service_count": service_count,
                "total_requests": total_requests,
                "successful_calls": total_successes,
                "failed_calls": total_failures,
                "success_rate": success_rate,
                "metrics_enabled": self.config.metrics_enabled,
                "tracing_enabled": self.config.tracing_enabled,
                "is_running": self._running
            }
    
    async def execute_cross_service_request(self, 
                                          source_type: ServiceType,
                                          target_type: ServiceType,
                                          action: Callable[[], Any]) -> Any:
        """Execute a request between services in the mesh."""
        source_service = await self.get_service(source_type)
        target_service = await self.get_service(target_type)
        
        if not source_service:
            raise ValueError(f"Source service {source_type} not found")
        if not target_service:
            raise ValueError(f"Target service {target_type} not found")
        
        logger.info(f"Cross-service request: {source_type} -> {target_type}")
        
        # Execute through the target service to get its resilience patterns
        return await target_service.process(action)
    
    async def broadcast_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an event to all services in the mesh."""
        try:
            metadata = Metadata()
            for key, value in data.items():
                metadata.set_string(key, str(value))
            
            event = Event(
                id=generate_id(),
                type=EventType.SYSTEM,
                timestamp=get_current_time(),
                resource=self.config.name,
                metadata=metadata
            )
            
            await self.event_bus.publish(event)
            logger.info(f"Broadcast event '{event_type}' to mesh")
            
        except Exception as e:
            logger.error(f"Failed to broadcast event: {e}")
            raise
    
    def is_running(self) -> bool:
        """Check if the service mesh is running."""
        return self._running


def create_service_mesh(name: str,
                       metrics_enabled: bool = True,
                       tracing_enabled: bool = True,
                       default_timeout: float = 30.0) -> ServiceMesh:
    """
    Create a new service mesh instance.
    
    Args:
        name: Name of the service mesh
        metrics_enabled: Enable metrics collection
        tracing_enabled: Enable distributed tracing
        default_timeout: Default timeout for operations
    
    Returns:
        ServiceMesh instance
    """
    config = Config(
        name=name,
        metrics_enabled=metrics_enabled,
        tracing_enabled=tracing_enabled,
        default_timeout=default_timeout
    )
    
    return ServiceMesh(config)


class ServiceHealthChecker:
    """Health checker for services in the mesh."""
    
    def __init__(self, mesh: ServiceMesh, check_interval: float = 30.0):
        self.mesh = mesh
        self.check_interval = check_interval
        self._running = False
        self._health_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start health checking."""
        if self._running:
            return
        
        self._running = True
        self._health_task = asyncio.create_task(self._health_check_loop())
        logger.info("Service health checker started")
    
    async def stop(self) -> None:
        """Stop health checking."""
        if not self._running:
            return
        
        self._running = False
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Service health checker stopped")
    
    async def _health_check_loop(self) -> None:
        """Main health checking loop."""
        try:
            while self._running:
                await self._check_all_services()
                await asyncio.sleep(self.check_interval)
        except asyncio.CancelledError:
            logger.info("Health check loop cancelled")
        except Exception as e:
            logger.error(f"Error in health check loop: {e}")
    
    async def _check_all_services(self) -> None:
        """Check health of all services."""
        services = await self.mesh.list_services()
        
        for service in services:
            try:
                await self._check_service_health(service)
            except Exception as e:
                logger.error(f"Health check failed for service {service.config.name}: {e}")
    
    async def _check_service_health(self, service: Service) -> None:
        """Check health of a specific service."""
        try:
            # Simple health check - try to get metrics
            metrics = await service.get_metrics()
            
            # Publish health status event
            await self.mesh.broadcast_event("health_check", {
                "service": service.config.name,
                "status": "healthy",
                "total_requests": metrics.total_requests,
                "success_rate": (metrics.successful_calls / metrics.total_requests * 100) 
                               if metrics.total_requests > 0 else 100
            })
            
        except Exception as e:
            # Publish unhealthy status
            await self.mesh.broadcast_event("health_check", {
                "service": service.config.name,
                "status": "unhealthy",
                "error": str(e)
            })
            raise