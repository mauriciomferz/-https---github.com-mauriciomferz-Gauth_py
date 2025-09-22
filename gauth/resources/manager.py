"""
Resource manager for handling service lifecycle and monitoring.
Provides centralized management of service configurations and state.
"""

import asyncio
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, AsyncIterator
import logging

from .types import ServiceType, ServiceStatus, ServiceConfig, ServiceMetrics

logger = logging.getLogger(__name__)


class ServiceNotFoundError(Exception):
    """Raised when a service is not found."""
    pass


class ConfigurationError(Exception):
    """Raised when there's an error in service configuration."""
    pass


class DependencyError(Exception):
    """Raised when there's a dependency resolution error."""
    pass


@dataclass
class ServiceState:
    """Tracks the current state of a service."""
    config: ServiceConfig
    metrics: ServiceMetrics = field(default_factory=ServiceMetrics)
    last_update: datetime = field(default_factory=datetime.now)
    last_check: datetime = field(default_factory=datetime.now)
    dependents: List[ServiceType] = field(default_factory=list)
    status: ServiceStatus = ServiceStatus.HEALTHY
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'config': self.config.to_dict(),
            'metrics': self.metrics.to_dict(),
            'last_update': self.last_update.isoformat(),
            'last_check': self.last_check.isoformat(),
            'dependents': [dep.value for dep in self.dependents],
            'status': self.status.value
        }


class ConfigStore(ABC):
    """Abstract interface for configuration storage."""
    
    @abstractmethod
    async def load(self, service_type: ServiceType) -> Optional[ServiceConfig]:
        """Load service configuration."""
        pass
    
    @abstractmethod
    async def save(self, config: ServiceConfig) -> None:
        """Save service configuration."""
        pass
    
    @abstractmethod
    async def list(self) -> List[ServiceConfig]:
        """List all service configurations."""
        pass
    
    @abstractmethod
    async def watch(self) -> AsyncIterator[ServiceConfig]:
        """Watch for configuration changes."""
        pass
    
    @abstractmethod
    async def delete(self, service_type: ServiceType) -> bool:
        """Delete service configuration."""
        pass


class MemoryConfigStore(ConfigStore):
    """In-memory configuration store for testing and development."""
    
    def __init__(self):
        self._configs: Dict[ServiceType, ServiceConfig] = {}
        self._watchers: List[asyncio.Queue] = []
        self._lock = threading.RLock()
    
    async def load(self, service_type: ServiceType) -> Optional[ServiceConfig]:
        """Load service configuration."""
        with self._lock:
            return self._configs.get(service_type)
    
    async def save(self, config: ServiceConfig) -> None:
        """Save service configuration."""
        config.updated_at = datetime.now()
        
        with self._lock:
            self._configs[config.type] = config
        
        # Notify watchers
        for watcher in self._watchers:
            try:
                watcher.put_nowait(config)
            except asyncio.QueueFull:
                logger.warning(f"Watcher queue full, dropping update for {config.type}")
    
    async def list(self) -> List[ServiceConfig]:
        """List all service configurations."""
        with self._lock:
            return list(self._configs.values())
    
    async def watch(self) -> AsyncIterator[ServiceConfig]:
        """Watch for configuration changes."""
        queue = asyncio.Queue(maxsize=100)
        self._watchers.append(queue)
        
        try:
            while True:
                config = await queue.get()
                yield config
        finally:
            self._watchers.remove(queue)
    
    async def delete(self, service_type: ServiceType) -> bool:
        """Delete service configuration."""
        with self._lock:
            if service_type in self._configs:
                del self._configs[service_type]
                return True
            return False


class ResourceManager:
    """Manages resource lifecycle and monitoring."""
    
    def __init__(self, config_store: ConfigStore, metrics_collector=None):
        self._config_store = config_store
        self._metrics_collector = metrics_collector
        self._services: Dict[ServiceType, ServiceState] = {}
        self._dependency_graph: Dict[ServiceType, Set[ServiceType]] = defaultdict(set)
        self._reverse_dependencies: Dict[ServiceType, Set[ServiceType]] = defaultdict(set)
        self._lock = threading.RLock()
        self._monitoring_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the resource manager."""
        self._running = True
        
        # Load existing configurations
        await self._load_configurations()
        
        # Start monitoring task
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Resource manager started")
    
    async def stop(self) -> None:
        """Stop the resource manager."""
        self._running = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Resource manager stopped")
    
    async def register_service(self, config: ServiceConfig) -> None:
        """Register a new service with the manager."""
        # Validate configuration
        self._validate_config(config)
        
        # Check dependencies
        await self._check_dependencies(config)
        
        # Create service state
        state = ServiceState(
            config=config,
            status=config.status
        )
        
        with self._lock:
            self._services[config.type] = state
            
            # Update dependency graph
            for dep in config.dependencies:
                self._dependency_graph[config.type].add(dep)
                self._reverse_dependencies[dep].add(config.type)
        
        # Save configuration
        await self._config_store.save(config)
        
        logger.info(f"Registered service: {config.type} ({config.name})")
    
    async def unregister_service(self, service_type: ServiceType) -> None:
        """Unregister a service from the manager."""
        with self._lock:
            if service_type not in self._services:
                raise ServiceNotFoundError(f"Service not found: {service_type}")
            
            # Check if any services depend on this one
            dependents = self._reverse_dependencies.get(service_type, set())
            if dependents:
                raise DependencyError(f"Cannot unregister {service_type}, depended on by: {dependents}")
            
            # Remove from graphs
            del self._services[service_type]
            
            # Clean up dependency graph
            for dep in self._dependency_graph[service_type]:
                self._reverse_dependencies[dep].discard(service_type)
            del self._dependency_graph[service_type]
        
        # Delete from store
        await self._config_store.delete(service_type)
        
        logger.info(f"Unregistered service: {service_type}")
    
    async def get_service(self, service_type: ServiceType) -> ServiceState:
        """Get service state."""
        with self._lock:
            if service_type not in self._services:
                raise ServiceNotFoundError(f"Service not found: {service_type}")
            return self._services[service_type]
    
    async def list_services(self) -> List[ServiceState]:
        """List all registered services."""
        with self._lock:
            return list(self._services.values())
    
    async def update_service_status(self, service_type: ServiceType, status: ServiceStatus) -> None:
        """Update service status."""
        with self._lock:
            if service_type not in self._services:
                raise ServiceNotFoundError(f"Service not found: {service_type}")
            
            state = self._services[service_type]
            state.status = status
            state.config.status = status
            state.last_update = datetime.now()
        
        # Save updated configuration
        await self._config_store.save(state.config)
        
        logger.info(f"Updated service status: {service_type} -> {status}")
    
    async def update_metrics(self, service_type: ServiceType, metrics: ServiceMetrics) -> None:
        """Update service metrics."""
        with self._lock:
            if service_type not in self._services:
                raise ServiceNotFoundError(f"Service not found: {service_type}")
            
            state = self._services[service_type]
            state.metrics = metrics
            state.last_check = datetime.now()
            
            # Update status based on metrics
            if metrics.is_healthy():
                new_status = ServiceStatus.HEALTHY
            elif metrics.is_degraded():
                new_status = ServiceStatus.DEGRADED
            else:
                new_status = ServiceStatus.UNHEALTHY
            
            if state.status != new_status:
                await self.update_service_status(service_type, new_status)
    
    async def get_dependency_graph(self) -> Dict[ServiceType, Set[ServiceType]]:
        """Get the dependency graph."""
        with self._lock:
            return dict(self._dependency_graph)
    
    async def get_service_dependencies(self, service_type: ServiceType) -> Set[ServiceType]:
        """Get dependencies for a specific service."""
        with self._lock:
            return self._dependency_graph.get(service_type, set()).copy()
    
    async def get_service_dependents(self, service_type: ServiceType) -> Set[ServiceType]:
        """Get services that depend on the specified service."""
        with self._lock:
            return self._reverse_dependencies.get(service_type, set()).copy()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check."""
        with self._lock:
            services = list(self._services.values())
        
        total_services = len(services)
        healthy_services = sum(1 for s in services if s.status == ServiceStatus.HEALTHY)
        degraded_services = sum(1 for s in services if s.status == ServiceStatus.DEGRADED)
        unhealthy_services = sum(1 for s in services if s.status == ServiceStatus.UNHEALTHY)
        
        overall_status = "healthy"
        if unhealthy_services > 0:
            overall_status = "unhealthy"
        elif degraded_services > 0:
            overall_status = "degraded"
        
        return {
            'overall_status': overall_status,
            'total_services': total_services,
            'healthy_services': healthy_services,
            'degraded_services': degraded_services,
            'unhealthy_services': unhealthy_services,
            'services': {s.config.type.value: s.to_dict() for s in services}
        }
    
    def _validate_config(self, config: ServiceConfig) -> None:
        """Validate service configuration."""
        if not config.name:
            raise ConfigurationError("Service name cannot be empty")
        
        if not config.version:
            raise ConfigurationError("Service version cannot be empty")
        
        if config.max_concurrency <= 0:
            raise ConfigurationError("Max concurrency must be positive")
        
        if config.timeout.total_seconds() <= 0:
            raise ConfigurationError("Timeout must be positive")
    
    async def _check_dependencies(self, config: ServiceConfig) -> None:
        """Check if all dependencies are available."""
        for dep in config.dependencies:
            if dep not in self._services:
                # Try to load from store
                dep_config = await self._config_store.load(dep)
                if not dep_config:
                    raise DependencyError(f"Dependency not found: {dep}")
    
    async def _load_configurations(self) -> None:
        """Load existing configurations from store."""
        configs = await self._config_store.list()
        
        # Sort by dependencies to ensure proper loading order
        sorted_configs = self._topological_sort(configs)
        
        for config in sorted_configs:
            try:
                await self.register_service(config)
            except Exception as e:
                logger.error(f"Failed to load service {config.type}: {e}")
    
    def _topological_sort(self, configs: List[ServiceConfig]) -> List[ServiceConfig]:
        """Sort configurations by dependency order."""
        # Simple topological sort
        config_map = {config.type: config for config in configs}
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(service_type: ServiceType):
            if service_type in temp_visited:
                raise DependencyError(f"Circular dependency detected involving {service_type}")
            
            if service_type in visited:
                return
            
            temp_visited.add(service_type)
            
            config = config_map.get(service_type)
            if config:
                for dep in config.dependencies:
                    visit(dep)
                
                visited.add(service_type)
                result.append(config)
            
            temp_visited.remove(service_type)
        
        for config in configs:
            if config.type not in visited:
                visit(config.type)
        
        return result
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(30)  # Check every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)  # Short delay on error
    
    async def _perform_health_checks(self) -> None:
        """Perform periodic health checks."""
        with self._lock:
            services = list(self._services.items())
        
        for service_type, state in services:
            try:
                # Simple health check based on last update time
                time_since_update = datetime.now() - state.last_check
                
                if time_since_update > timedelta(minutes=5):
                    # Service hasn't been updated in 5 minutes, mark as unhealthy
                    if state.status != ServiceStatus.UNHEALTHY:
                        await self.update_service_status(service_type, ServiceStatus.UNHEALTHY)
                        logger.warning(f"Service {service_type} marked unhealthy due to no recent updates")
                
            except Exception as e:
                logger.error(f"Error checking health for {service_type}: {e}")