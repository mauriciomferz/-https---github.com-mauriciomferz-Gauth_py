"""
Service registry implementations for the GAuth service mesh.

This module provides different service registry backends including
Redis-based and in-memory implementations for service discovery.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime, timedelta

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .mesh import ServiceRegistry, ServiceInfo, ServiceID
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class RedisRegistry(ServiceRegistry):
    """Redis-based service registry implementation."""
    
    def __init__(self, 
                 redis_client: Any,
                 key_prefix: str = "mesh:service:",
                 expiration: float = 60.0):
        """
        Initialize Redis registry.
        
        Args:
            redis_client: Redis async client instance
            key_prefix: Prefix for Redis keys
            expiration: Key expiration time in seconds
        """
        if not REDIS_AVAILABLE:
            raise ImportError("redis package is required for RedisRegistry")
        
        self.client = redis_client
        self.key_prefix = key_prefix
        self.expiration = expiration
        self._watchers: List[asyncio.Queue] = []
        self._refresh_tasks: Dict[ServiceID, asyncio.Task] = {}
    
    def _service_key(self, service_id: ServiceID) -> str:
        """Generate Redis key for a service."""
        return f"{self.key_prefix}{service_id}"
    
    async def register(self, info: ServiceInfo) -> None:
        """Register a service in Redis."""
        try:
            data = json.dumps(info.to_dict())
            key = self._service_key(info.id)
            
            # Set with expiration
            await self.client.set(key, data, ex=int(self.expiration))
            
            # Notify watchers
            for watcher in self._watchers:
                try:
                    watcher.put_nowait(info)
                except asyncio.QueueFull:
                    logger.warning("Watcher queue full, skipping notification")
            
            # Start refresh task to keep the service alive
            if info.id in self._refresh_tasks:
                self._refresh_tasks[info.id].cancel()
            
            self._refresh_tasks[info.id] = asyncio.create_task(
                self._refresh_loop(info)
            )
            
            logger.info(f"Registered service {info.id} in Redis")
            
        except Exception as e:
            logger.error(f"Failed to register service {info.id}: {e}")
            raise
    
    async def unregister(self, service_id: ServiceID) -> None:
        """Unregister a service from Redis."""
        try:
            key = self._service_key(service_id)
            await self.client.delete(key)
            
            # Cancel refresh task
            if service_id in self._refresh_tasks:
                self._refresh_tasks[service_id].cancel()
                del self._refresh_tasks[service_id]
            
            logger.info(f"Unregistered service {service_id} from Redis")
            
        except Exception as e:
            logger.error(f"Failed to unregister service {service_id}: {e}")
            raise
    
    async def get_service(self, service_id: ServiceID) -> Optional[ServiceInfo]:
        """Get service information from Redis."""
        try:
            key = self._service_key(service_id)
            data = await self.client.get(key)
            
            if data is None:
                return None
            
            service_data = json.loads(data)
            return ServiceInfo.from_dict(service_data)
            
        except Exception as e:
            logger.error(f"Failed to get service {service_id}: {e}")
            return None
    
    async def list_services(self) -> List[ServiceInfo]:
        """List all services from Redis."""
        try:
            pattern = f"{self.key_prefix}*"
            keys = await self.client.keys(pattern)
            
            services = []
            if keys:
                # Get all service data in batch
                values = await self.client.mget(keys)
                
                for value in values:
                    if value:
                        try:
                            service_data = json.loads(value)
                            services.append(ServiceInfo.from_dict(service_data))
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning(f"Failed to parse service data: {e}")
            
            return services
            
        except Exception as e:
            logger.error(f"Failed to list services: {e}")
            return []
    
    async def watch(self) -> AsyncGenerator[ServiceInfo, None]:
        """Watch for service changes using Redis pub/sub."""
        watcher = asyncio.Queue(maxsize=100)
        self._watchers.append(watcher)
        
        try:
            while True:
                try:
                    # Wait for notifications with timeout
                    service_info = await asyncio.wait_for(
                        watcher.get(), timeout=30.0
                    )
                    if service_info is None:  # End signal
                        break
                    yield service_info
                except asyncio.TimeoutError:
                    # Yield current services periodically
                    services = await self.list_services()
                    for service in services:
                        yield service
        finally:
            if watcher in self._watchers:
                self._watchers.remove(watcher)
    
    async def _refresh_loop(self, info: ServiceInfo) -> None:
        """Refresh service registration to keep it alive."""
        try:
            refresh_interval = self.expiration / 2
            
            while True:
                await asyncio.sleep(refresh_interval)
                
                # Re-register to refresh expiration
                try:
                    await self.register(info)
                except Exception as e:
                    logger.error(f"Failed to refresh service {info.id}: {e}")
                    break
                    
        except asyncio.CancelledError:
            logger.debug(f"Refresh loop cancelled for service {info.id}")
        except Exception as e:
            logger.error(f"Error in refresh loop for service {info.id}: {e}")
    
    async def close(self) -> None:
        """Close the registry and cleanup resources."""
        # Cancel all refresh tasks
        for task in self._refresh_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._refresh_tasks:
            await asyncio.gather(
                *self._refresh_tasks.values(),
                return_exceptions=True
            )
        
        self._refresh_tasks.clear()
        
        # Signal watchers to stop
        for watcher in self._watchers:
            watcher.put_nowait(None)
        
        self._watchers.clear()


class InMemoryRegistry(ServiceRegistry):
    """In-memory service registry implementation."""
    
    def __init__(self):
        """Initialize in-memory registry."""
        self._services: Dict[ServiceID, ServiceInfo] = {}
        self._watchers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()
    
    async def register(self, info: ServiceInfo) -> None:
        """Register a service in memory."""
        async with self._lock:
            self._services[info.id] = info
            
            # Notify watchers
            for watcher in self._watchers:
                try:
                    watcher.put_nowait(info)
                except asyncio.QueueFull:
                    logger.warning("Watcher queue full, skipping notification")
            
            logger.info(f"Registered service {info.id} in memory")
    
    async def unregister(self, service_id: ServiceID) -> None:
        """Unregister a service from memory."""
        async with self._lock:
            if service_id in self._services:
                del self._services[service_id]
                logger.info(f"Unregistered service {service_id} from memory")
    
    async def get_service(self, service_id: ServiceID) -> Optional[ServiceInfo]:
        """Get service information from memory."""
        async with self._lock:
            return self._services.get(service_id)
    
    async def list_services(self) -> List[ServiceInfo]:
        """List all services from memory."""
        async with self._lock:
            return list(self._services.values())
    
    async def watch(self) -> AsyncGenerator[ServiceInfo, None]:
        """Watch for service changes."""
        watcher = asyncio.Queue(maxsize=100)
        self._watchers.append(watcher)
        
        try:
            # Yield current services first
            async with self._lock:
                for service in self._services.values():
                    yield service
            
            # Then watch for changes
            while True:
                service_info = await watcher.get()
                if service_info is None:  # End signal
                    break
                yield service_info
        finally:
            if watcher in self._watchers:
                self._watchers.remove(watcher)
    
    async def close(self) -> None:
        """Close the registry and cleanup resources."""
        async with self._lock:
            # Signal watchers to stop
            for watcher in self._watchers:
                watcher.put_nowait(None)
            
            self._watchers.clear()
            self._services.clear()


class ConsulRegistry(ServiceRegistry):
    """Consul-based service registry implementation."""
    
    def __init__(self, consul_client: Any, datacenter: str = "dc1"):
        """
        Initialize Consul registry.
        
        Args:
            consul_client: Consul client instance
            datacenter: Consul datacenter name
        """
        self.client = consul_client
        self.datacenter = datacenter
        self._watchers: List[asyncio.Queue] = []
    
    async def register(self, info: ServiceInfo) -> None:
        """Register a service in Consul."""
        try:
            # Convert ServiceInfo to Consul service registration format
            service_data = {
                'ID': str(info.id),
                'Name': info.name,
                'Tags': [f"version:{info.version}"] + [f"{k}:{v}" for k, v in info.metadata.items()],
                'Port': int(info.metadata.get('port', 8080)),
                'Check': {
                    'HTTP': f"http://localhost:{info.metadata.get('port', 8080)}/health",
                    'Interval': '10s'
                }
            }
            
            # Register with Consul
            await self.client.agent.service.register(**service_data)
            
            # Notify watchers
            for watcher in self._watchers:
                try:
                    watcher.put_nowait(info)
                except asyncio.QueueFull:
                    logger.warning("Watcher queue full, skipping notification")
            
            logger.info(f"Registered service {info.id} in Consul")
            
        except Exception as e:
            logger.error(f"Failed to register service {info.id} in Consul: {e}")
            raise
    
    async def unregister(self, service_id: ServiceID) -> None:
        """Unregister a service from Consul."""
        try:
            await self.client.agent.service.deregister(str(service_id))
            logger.info(f"Unregistered service {service_id} from Consul")
            
        except Exception as e:
            logger.error(f"Failed to unregister service {service_id} from Consul: {e}")
            raise
    
    async def get_service(self, service_id: ServiceID) -> Optional[ServiceInfo]:
        """Get service information from Consul."""
        try:
            services = await self.client.agent.service.list()
            
            service_data = services.get(str(service_id))
            if not service_data:
                return None
            
            # Convert Consul service data to ServiceInfo
            metadata = {}
            for tag in service_data.get('Tags', []):
                if ':' in tag:
                    key, value = tag.split(':', 1)
                    metadata[key] = value
            
            return ServiceInfo(
                id=ServiceID(service_data['ID']),
                name=service_data['Service'],
                version=metadata.get('version', '1.0.0'),
                endpoints=[f"http://localhost:{service_data['Port']}"],
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to get service {service_id} from Consul: {e}")
            return None
    
    async def list_services(self) -> List[ServiceInfo]:
        """List all services from Consul."""
        try:
            services = await self.client.agent.service.list()
            service_list = []
            
            for service_data in services.values():
                metadata = {}
                for tag in service_data.get('Tags', []):
                    if ':' in tag:
                        key, value = tag.split(':', 1)
                        metadata[key] = value
                
                service_info = ServiceInfo(
                    id=ServiceID(service_data['ID']),
                    name=service_data['Service'],
                    version=metadata.get('version', '1.0.0'),
                    endpoints=[f"http://localhost:{service_data['Port']}"],
                    metadata=metadata
                )
                service_list.append(service_info)
            
            return service_list
            
        except Exception as e:
            logger.error(f"Failed to list services from Consul: {e}")
            return []
    
    async def watch(self) -> AsyncGenerator[ServiceInfo, None]:
        """Watch for service changes in Consul."""
        watcher = asyncio.Queue(maxsize=100)
        self._watchers.append(watcher)
        
        try:
            # Poll for changes (simplified implementation)
            last_services = set()
            
            while True:
                try:
                    current_services = await self.list_services()
                    current_ids = {service.id for service in current_services}
                    
                    # Yield new or updated services
                    for service in current_services:
                        if service.id not in last_services:
                            yield service
                    
                    last_services = current_ids
                    await asyncio.sleep(5)  # Poll every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Error watching Consul services: {e}")
                    await asyncio.sleep(10)
                    
        finally:
            if watcher in self._watchers:
                self._watchers.remove(watcher)
    
    async def close(self) -> None:
        """Close the registry and cleanup resources."""
        # Signal watchers to stop
        for watcher in self._watchers:
            watcher.put_nowait(None)
        
        self._watchers.clear()


def create_redis_registry(redis_url: str = "redis://localhost:6379",
                         key_prefix: str = "mesh:service:",
                         expiration: float = 60.0) -> RedisRegistry:
    """
    Create a Redis-based service registry.
    
    Args:
        redis_url: Redis connection URL
        key_prefix: Prefix for Redis keys
        expiration: Key expiration time in seconds
    
    Returns:
        RedisRegistry instance
    """
    if not REDIS_AVAILABLE:
        raise ImportError("redis package is required for RedisRegistry")
    
    redis_client = redis.from_url(redis_url)
    return RedisRegistry(redis_client, key_prefix, expiration)


def create_memory_registry() -> InMemoryRegistry:
    """
    Create an in-memory service registry.
    
    Returns:
        InMemoryRegistry instance
    """
    return InMemoryRegistry()


def create_consul_registry(consul_host: str = "localhost",
                          consul_port: int = 8500,
                          datacenter: str = "dc1") -> ConsulRegistry:
    """
    Create a Consul-based service registry.
    
    Args:
        consul_host: Consul server host
        consul_port: Consul server port
        datacenter: Consul datacenter name
    
    Returns:
        ConsulRegistry instance
    """
    try:
        import consul.aio as consul
        consul_client = consul.Consul(host=consul_host, port=consul_port)
        return ConsulRegistry(consul_client, datacenter)
    except ImportError:
        raise ImportError("python-consul package is required for ConsulRegistry")