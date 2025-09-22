"""
Service mesh integration module for GAuth.

This module provides service mesh functionality including service discovery,
registry management, authentication, authorization, and traffic management.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, AsyncGenerator
from enum import Enum
import logging
import ssl
from datetime import datetime, timedelta

from ..auth.authenticator import Authenticator
from ..authz.authorizer import Authorizer, Subject, Resource, Action, Permission
from ..metrics.collector import MetricsCollector
from ..common.messages import ErrorMessages, InfoMessages
from ..common.utils import generate_id, get_current_time, validate_string


logger = logging.getLogger(__name__)


class ServiceID:
    """Unique identifier for a service in the mesh."""
    
    def __init__(self, value: str):
        if not validate_string(value, min_length=1, max_length=100):
            raise ValueError("Invalid service ID")
        self._value = value
    
    def __str__(self) -> str:
        return self._value
    
    def __eq__(self, other) -> bool:
        if isinstance(other, ServiceID):
            return self._value == other._value
        return False
    
    def __hash__(self) -> int:
        return hash(self._value)
    
    @property
    def value(self) -> str:
        return self._value


@dataclass
class ServiceInfo:
    """Information about a service in the mesh."""
    
    id: ServiceID
    name: str
    version: str
    endpoints: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    permissions: List[Permission] = field(default_factory=list)
    auth_config: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': str(self.id),
            'name': self.name,
            'version': self.version,
            'endpoints': self.endpoints,
            'metadata': self.metadata,
            'permissions': [p.to_dict() for p in self.permissions],
            'auth_config': self.auth_config
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ServiceInfo':
        """Create from dictionary."""
        return cls(
            id=ServiceID(data['id']),
            name=data['name'],
            version=data['version'],
            endpoints=data.get('endpoints', []),
            metadata=data.get('metadata', {}),
            permissions=[Permission.from_dict(p) for p in data.get('permissions', [])],
            auth_config=data.get('auth_config')
        )


class ServiceRegistry(ABC):
    """Abstract base class for service registries."""
    
    @abstractmethod
    async def register(self, info: ServiceInfo) -> None:
        """Register a service in the registry."""
        pass
    
    @abstractmethod
    async def unregister(self, service_id: ServiceID) -> None:
        """Unregister a service from the registry."""
        pass
    
    @abstractmethod
    async def get_service(self, service_id: ServiceID) -> Optional[ServiceInfo]:
        """Get service information by ID."""
        pass
    
    @abstractmethod
    async def list_services(self) -> List[ServiceInfo]:
        """List all registered services."""
        pass
    
    @abstractmethod
    async def watch(self) -> AsyncGenerator[ServiceInfo, None]:
        """Watch for service changes."""
        pass


@dataclass
class RetryConfig:
    """Configuration for request retry behavior."""
    
    max_retries: int = 3
    backoff_base: float = 0.1  # seconds
    max_backoff: float = 5.0   # seconds
    
    def calculate_backoff(self, attempt: int) -> float:
        """Calculate backoff time for given attempt."""
        backoff = self.backoff_base * (2 ** attempt)
        return min(backoff, self.max_backoff)


@dataclass
class MeshConfig:
    """Configuration for the service mesh."""
    
    service_id: ServiceID
    registry: ServiceRegistry
    authenticator: Authenticator
    authorizer: Authorizer
    metrics_collector: Optional[MetricsCollector] = None
    tls_config: Optional[ssl.SSLContext] = None
    health_check_interval: float = 30.0  # seconds
    retry_config: Optional[RetryConfig] = None
    
    def __post_init__(self):
        if self.retry_config is None:
            self.retry_config = RetryConfig()


class ServiceStatus:
    """Represents the current status of a service."""
    
    def __init__(self):
        self.healthy: bool = True
        self.last_check: datetime = get_current_time()
        self.last_error: Optional[str] = None
        self.retry_count: int = 0
    
    def mark_healthy(self):
        """Mark service as healthy."""
        self.healthy = True
        self.last_check = get_current_time()
        self.last_error = None
        self.retry_count = 0
    
    def mark_unhealthy(self, error: str):
        """Mark service as unhealthy."""
        self.healthy = False
        self.last_check = get_current_time()
        self.last_error = error
        self.retry_count += 1


class Mesh:
    """Service mesh implementation."""
    
    def __init__(self, config: MeshConfig):
        self.config = config
        self._services: Dict[ServiceID, ServiceInfo] = {}
        self._status: Dict[ServiceID, ServiceStatus] = {}
        self._watchers: List[asyncio.Queue] = []
        self._running = False
        self._health_check_task: Optional[asyncio.Task] = None
        self._watch_task: Optional[asyncio.Task] = None
        
        # Validate required components
        if not config.registry:
            raise ValueError("Service registry is required")
        if not config.authenticator:
            raise ValueError("Authenticator is required")
        if not config.authorizer:
            raise ValueError("Authorizer is required")
    
    async def start(self) -> None:
        """Initialize and start the mesh."""
        if self._running:
            logger.warning("Mesh is already running")
            return
        
        try:
            # Register this service
            info = ServiceInfo(
                id=self.config.service_id,
                name=f"service-{self.config.service_id}",
                version="1.0.0"
            )
            await self.config.registry.register(info)
            logger.info(f"Registered service {self.config.service_id}")
            
            # Start watching for service changes
            self._watch_task = asyncio.create_task(self._watch_services())
            
            # Start health checks
            self._health_check_task = asyncio.create_task(self._run_health_checks())
            
            self._running = True
            logger.info("Service mesh started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start service mesh: {e}")
            raise
    
    async def stop(self) -> None:
        """Gracefully shut down the mesh."""
        if not self._running:
            return
        
        try:
            # Cancel background tasks
            if self._watch_task:
                self._watch_task.cancel()
                try:
                    await self._watch_task
                except asyncio.CancelledError:
                    pass
            
            if self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass
            
            # Unregister this service
            await self.config.registry.unregister(self.config.service_id)
            
            # Close watchers
            for watcher in self._watchers:
                watcher.put_nowait(None)  # Signal end
            
            self._running = False
            logger.info("Service mesh stopped")
            
        except Exception as e:
            logger.error(f"Error stopping service mesh: {e}")
            raise
    
    async def get_service(self, service_id: ServiceID) -> Optional[ServiceInfo]:
        """Get service information."""
        # Check local cache first
        if service_id in self._services:
            return self._services[service_id]
        
        # Fetch from registry
        info = await self.config.registry.get_service(service_id)
        if info:
            self._services[service_id] = info
            if service_id not in self._status:
                self._status[service_id] = ServiceStatus()
        
        return info
    
    async def authenticate(self, service_id: ServiceID, credentials: Any) -> None:
        """Authenticate a service."""
        try:
            # Validate credentials using the authenticator
            await self.config.authenticator.validate_credentials(credentials)
            
            if self.config.metrics_collector:
                await self.config.metrics_collector.record_auth_attempt("mesh", "success")
            
            logger.info(f"Service {service_id} authenticated successfully")
            
        except Exception as e:
            if self.config.metrics_collector:
                await self.config.metrics_collector.record_auth_attempt("mesh", "failure")
            
            logger.error(f"Authentication failed for service {service_id}: {e}")
            raise ValueError(f"Service authentication failed: {e}")
    
    async def authorize(self, source: ServiceID, target: ServiceID, action: str) -> None:
        """Check if a service can access another service."""
        try:
            subject = Subject(id=str(source), type="service")
            resource = Resource(id=str(target), type="service")
            act = Action(id=action, type="operation")
            
            decision = await self.config.authorizer.authorize(subject, act, resource)
            
            if not decision or not decision.allowed:
                reason = decision.reason if decision else "unknown"
                error_msg = f"Service {source} not authorized to {action} on {target}: {reason}"
                logger.warning(error_msg)
                raise PermissionError(error_msg)
            
            logger.info(f"Authorization granted: {source} -> {action} on {target}")
            
        except Exception as e:
            logger.error(f"Authorization check failed: {e}")
            raise
    
    async def execute_request(self, target: ServiceID, request: Any) -> Any:
        """Execute a mesh-aware request with retry logic."""
        # Get service info
        service_info = await self.get_service(target)
        if not service_info:
            raise ValueError(f"Service not found: {target}")
        
        # Check service health
        if target in self._status:
            status = self._status[target]
            if not status.healthy and status.retry_count >= self.config.retry_config.max_retries:
                raise RuntimeError(f"Service {target} is unhealthy")
        
        # Execute request with retries
        last_error = None
        for attempt in range(self.config.retry_config.max_retries + 1):
            try:
                # This is a placeholder for actual request execution
                # In a real implementation, this would make HTTP requests,
                # gRPC calls, or other inter-service communication
                result = await self._execute_request_impl(service_info, request)
                
                # Mark service as healthy on success
                if target in self._status:
                    self._status[target].mark_healthy()
                
                if self.config.metrics_collector:
                    await self.config.metrics_collector.record_request_success(str(target))
                
                return result
                
            except Exception as e:
                last_error = e
                
                # Mark service as unhealthy
                if target not in self._status:
                    self._status[target] = ServiceStatus()
                self._status[target].mark_unhealthy(str(e))
                
                if self.config.metrics_collector:
                    await self.config.metrics_collector.record_request_failure(str(target))
                
                if attempt < self.config.retry_config.max_retries:
                    backoff = self.config.retry_config.calculate_backoff(attempt)
                    logger.warning(f"Request to {target} failed (attempt {attempt + 1}), retrying in {backoff}s: {e}")
                    await asyncio.sleep(backoff)
                else:
                    logger.error(f"Request to {target} failed after {attempt + 1} attempts: {e}")
        
        raise RuntimeError(f"Request to {target} failed after all retries: {last_error}")
    
    async def _execute_request_impl(self, service_info: ServiceInfo, request: Any) -> Any:
        """Placeholder for actual request execution implementation."""
        # This would be implemented based on the specific communication protocol
        # (HTTP, gRPC, message queues, etc.)
        await asyncio.sleep(0.01)  # Simulate network delay
        return {"status": "success", "data": "mock_response"}
    
    async def _watch_services(self) -> None:
        """Watch for service registry changes."""
        try:
            async for service_info in self.config.registry.watch():
                if service_info:
                    self._services[service_info.id] = service_info
                    if service_info.id not in self._status:
                        self._status[service_info.id] = ServiceStatus()
                    
                    # Notify watchers
                    for watcher in self._watchers:
                        try:
                            watcher.put_nowait(service_info)
                        except asyncio.QueueFull:
                            logger.warning("Watcher queue full, skipping notification")
                    
                    logger.info(f"Service updated: {service_info.id}")
        
        except asyncio.CancelledError:
            logger.info("Service watcher cancelled")
        except Exception as e:
            logger.error(f"Error watching services: {e}")
    
    async def _run_health_checks(self) -> None:
        """Run periodic health checks for all services."""
        try:
            while self._running:
                await asyncio.sleep(self.config.health_check_interval)
                
                # Check health of all known services
                for service_id in list(self._services.keys()):
                    asyncio.create_task(self._check_service_health(service_id))
        
        except asyncio.CancelledError:
            logger.info("Health checker cancelled")
        except Exception as e:
            logger.error(f"Error in health check loop: {e}")
    
    async def _check_service_health(self, service_id: ServiceID) -> None:
        """Check the health of a specific service."""
        try:
            # This is a placeholder for actual health check implementation
            # In a real implementation, this would ping the service endpoints
            service_info = self._services.get(service_id)
            if not service_info:
                return
            
            # Simulate health check
            await asyncio.sleep(0.01)
            
            # Assume service is healthy for now
            if service_id not in self._status:
                self._status[service_id] = ServiceStatus()
            self._status[service_id].mark_healthy()
            
        except Exception as e:
            logger.error(f"Health check failed for service {service_id}: {e}")
            if service_id not in self._status:
                self._status[service_id] = ServiceStatus()
            self._status[service_id].mark_unhealthy(str(e))
    
    def add_watcher(self) -> asyncio.Queue:
        """Add a watcher for service changes."""
        watcher = asyncio.Queue(maxsize=100)
        self._watchers.append(watcher)
        return watcher
    
    def remove_watcher(self, watcher: asyncio.Queue) -> None:
        """Remove a service change watcher."""
        if watcher in self._watchers:
            self._watchers.remove(watcher)
    
    def get_service_status(self, service_id: ServiceID) -> Optional[ServiceStatus]:
        """Get the current status of a service."""
        return self._status.get(service_id)
    
    def get_all_services(self) -> Dict[ServiceID, ServiceInfo]:
        """Get all cached service information."""
        return self._services.copy()
    
    def is_running(self) -> bool:
        """Check if the mesh is currently running."""
        return self._running


def create_mesh(config: MeshConfig) -> Mesh:
    """Create a new service mesh instance."""
    return Mesh(config)