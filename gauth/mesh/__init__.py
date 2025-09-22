"""
GAuth Mesh Package

Service mesh integration for microservice architectures.
Provides service discovery, registry management, authentication, authorization,
and traffic management capabilities.
"""

from .mesh import (
    Mesh,
    MeshConfig,
    ServiceID,
    ServiceInfo,
    ServiceRegistry,
    ServiceStatus,
    RetryConfig,
    create_mesh
)

from .registry import (
    RedisRegistry,
    InMemoryRegistry,
    ConsulRegistry,
    create_redis_registry,
    create_memory_registry,
    create_consul_registry
)

from .service import (
    Service,
    ServiceMesh,
    Config,
    ServiceHealthChecker,
    create_service_mesh
)


__all__ = [
    # Core mesh functionality
    'Mesh',
    'MeshConfig',
    'ServiceID',
    'ServiceInfo',
    'ServiceRegistry',
    'ServiceStatus',
    'RetryConfig',
    'create_mesh',
    
    # Service registries
    'RedisRegistry',
    'InMemoryRegistry',
    'ConsulRegistry',
    'create_redis_registry',
    'create_memory_registry',
    'create_consul_registry',
    
    # Service management
    'Service',
    'ServiceMesh',
    'Config',
    'ServiceHealthChecker',
    'create_service_mesh'
]


# Package metadata
__version__ = '1.0.0'
__author__ = 'GAuth Team'
__description__ = 'Service mesh integration for GAuth microservice architectures'