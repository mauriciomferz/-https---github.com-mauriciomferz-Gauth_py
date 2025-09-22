"""
Resource package for GAuth.

This package provides comprehensive resource management including
resource definitions, validation, lifecycle management, and storage.
"""

from .types import (
    Resource,
    ResourceType,
    ResourceStatus,
    AccessLevel,
    ResourceConfig,
    RateLimit,
    ResourceError,
    ResourceNotFoundError,
    ResourceValidationError,
    create_resource,
    create_api_resource,
    create_service_resource,
    create_data_resource
)

from .manager import (
    ResourceStore,
    InMemoryResourceStore,
    FileResourceStore,
    ResourceManager,
    create_resource_manager
)

from .config import (
    LifecycleEvent,
    LifecycleHook,
    ResourceValidator,
    ScopeValidator,
    NameValidator,
    ConfigValidator,
    ResourceTemplate,
    LifecycleManager,
    API_RESOURCE_TEMPLATE,
    SERVICE_RESOURCE_TEMPLATE,
    DATA_RESOURCE_TEMPLATE,
    create_lifecycle_manager,
    get_predefined_templates
)

__all__ = [
    # Types
    "Resource",
    "ResourceType",
    "ResourceStatus",
    "AccessLevel",
    "ResourceConfig",
    "RateLimit",
    "ResourceError",
    "ResourceNotFoundError",
    "ResourceValidationError",
    "create_resource",
    "create_api_resource",
    "create_service_resource",
    "create_data_resource",
    
    # Manager
    "ResourceStore",
    "InMemoryResourceStore",
    "FileResourceStore",
    "ResourceManager",
    "create_resource_manager",
    
    # Config
    "LifecycleEvent",
    "LifecycleHook",
    "ResourceValidator",
    "ScopeValidator",
    "NameValidator",
    "ConfigValidator",
    "ResourceTemplate",
    "LifecycleManager",
    "API_RESOURCE_TEMPLATE",
    "SERVICE_RESOURCE_TEMPLATE",
    "DATA_RESOURCE_TEMPLATE",
    "create_lifecycle_manager",
    "get_predefined_templates"
]

__version__ = "1.0.0"