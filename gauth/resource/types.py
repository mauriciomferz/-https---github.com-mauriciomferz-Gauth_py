"""
Resource types and definitions for GAuth.

This module provides comprehensive resource management including
resource definitions, validation, and lifecycle management.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Set
import re

from ..common.utils import get_current_time, generate_id, validate_string
from ..common.messages import ErrorMessages


logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Enumeration of resource types."""
    
    API = "api"
    SERVICE = "service" 
    ENDPOINT = "endpoint"
    DATA = "data"
    FILE = "file"
    DATABASE = "database"
    QUEUE = "queue"
    TOPIC = "topic"
    FUNCTION = "function"
    CONTAINER = "container"


class ResourceStatus(Enum):
    """Enumeration of resource statuses."""
    
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"
    MAINTENANCE = "maintenance"
    PROVISIONING = "provisioning"
    DECOMMISSIONED = "decommissioned"


class AccessLevel(Enum):
    """Enumeration of access levels."""
    
    PUBLIC = "public"
    PROTECTED = "protected"
    PRIVATE = "private"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"


class ResourceError(Exception):
    """Base exception for resource errors."""
    pass


class ResourceValidationError(ResourceError):
    """Exception raised when resource validation fails."""
    pass


class ResourceNotFoundError(ResourceError):
    """Exception raised when resource is not found."""
    pass


@dataclass
class RateLimit:
    """Rate limiting configuration for resources."""
    
    requests_per_second: int = 100
    burst_size: int = 10
    window_size: int = 60  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requests_per_second": self.requests_per_second,
            "burst_size": self.burst_size,
            "window_size": self.window_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RateLimit':
        """Create from dictionary."""
        return cls(
            requests_per_second=data.get("requests_per_second", 100),
            burst_size=data.get("burst_size", 10),
            window_size=data.get("window_size", 60)
        )


@dataclass
class ConfigValue:
    """Typed value for resource configuration."""
    
    type: str
    data: Any
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "data": self.data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigValue':
        """Create from dictionary."""
        return cls(
            type=data["type"],
            data=data["data"]
        )


class ResourceConfig:
    """Structured configuration for resources."""
    
    def __init__(self):
        """Initialize resource configuration."""
        self.settings: Dict[str, ConfigValue] = {}
    
    def set_string(self, key: str, value: str) -> None:
        """Set a string value in the configuration."""
        self.settings[key] = ConfigValue(type="string", data=value)
    
    def set_int(self, key: str, value: int) -> None:
        """Set an integer value in the configuration."""
        self.settings[key] = ConfigValue(type="int", data=value)
    
    def set_float(self, key: str, value: float) -> None:
        """Set a float value in the configuration."""
        self.settings[key] = ConfigValue(type="float", data=value)
    
    def set_bool(self, key: str, value: bool) -> None:
        """Set a boolean value in the configuration."""
        self.settings[key] = ConfigValue(type="bool", data=value)
    
    def set_map(self, key: str, value: Dict[str, Any]) -> None:
        """Set a map value in the configuration."""
        self.settings[key] = ConfigValue(type="map", data=value)
    
    def set_list(self, key: str, value: List[Any]) -> None:
        """Set a list value in the configuration."""
        self.settings[key] = ConfigValue(type="list", data=value)
    
    def get_string(self, key: str, default: str = "") -> str:
        """Get a string value from the configuration."""
        if key in self.settings and self.settings[key].type == "string":
            return self.settings[key].data
        return default
    
    def get_int(self, key: str, default: int = 0) -> int:
        """Get an integer value from the configuration."""
        if key in self.settings and self.settings[key].type == "int":
            return self.settings[key].data
        return default
    
    def get_float(self, key: str, default: float = 0.0) -> float:
        """Get a float value from the configuration."""
        if key in self.settings and self.settings[key].type == "float":
            return self.settings[key].data
        return default
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get a boolean value from the configuration."""
        if key in self.settings and self.settings[key].type == "bool":
            return self.settings[key].data
        return default
    
    def get_map(self, key: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get a map value from the configuration."""
        if key in self.settings and self.settings[key].type == "map":
            return self.settings[key].data
        return default or {}
    
    def get_list(self, key: str, default: Optional[List[Any]] = None) -> List[Any]:
        """Get a list value from the configuration."""
        if key in self.settings and self.settings[key].type == "list":
            return self.settings[key].data
        return default or []
    
    def has(self, key: str) -> bool:
        """Check if a key exists in the configuration."""
        return key in self.settings
    
    def remove(self, key: str) -> None:
        """Remove a key from the configuration."""
        if key in self.settings:
            del self.settings[key]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            key: value.to_dict() for key, value in self.settings.items()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceConfig':
        """Create from dictionary."""
        config = cls()
        for key, value_data in data.items():
            config.settings[key] = ConfigValue.from_dict(value_data)
        return config


@dataclass
class Resource:
    """Represents a protected resource with comprehensive metadata."""
    
    # Core fields
    id: str
    type: ResourceType
    name: str
    description: str = ""
    version: str = "1.0.0"
    status: ResourceStatus = ResourceStatus.ACTIVE
    
    # Access control
    owner_id: str = ""
    access_level: AccessLevel = AccessLevel.PROTECTED
    scopes: List[str] = field(default_factory=list)
    
    # Routing
    path: str = ""
    methods: List[str] = field(default_factory=lambda: ["GET"])
    
    # Availability
    region: str = "default"
    environment: str = "production"
    
    # Rate limiting
    rate_limit: Optional[RateLimit] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=get_current_time)
    updated_at: datetime = field(default_factory=get_current_time)
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    config: ResourceConfig = field(default_factory=ResourceConfig)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.id:
            self.id = generate_id()
        
        if not self.name:
            self.name = f"{self.type.value}_{self.id[:8]}"
        
        # Ensure enum values
        if isinstance(self.type, str):
            self.type = ResourceType(self.type)
        if isinstance(self.status, str):
            self.status = ResourceStatus(self.status)
        if isinstance(self.access_level, str):
            self.access_level = AccessLevel(self.access_level)
    
    def validate(self) -> None:
        """Validate the resource configuration."""
        errors = []
        
        # Validate ID
        if not validate_string(self.id, min_length=1, max_length=100):
            errors.append("Resource ID must be 1-100 characters")
        
        # Validate name
        if not validate_string(self.name, min_length=1, max_length=200):
            errors.append("Resource name must be 1-200 characters")
        
        # Validate path if provided
        if self.path and not self._validate_path(self.path):
            errors.append("Invalid resource path format")
        
        # Validate methods
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        for method in self.methods:
            if method.upper() not in valid_methods:
                errors.append(f"Invalid HTTP method: {method}")
        
        # Validate scopes
        for scope in self.scopes:
            if not validate_string(scope, min_length=1, max_length=50):
                errors.append(f"Invalid scope: {scope}")
        
        # Validate rate limit
        if self.rate_limit:
            if self.rate_limit.requests_per_second <= 0:
                errors.append("Rate limit requests_per_second must be positive")
            if self.rate_limit.burst_size <= 0:
                errors.append("Rate limit burst_size must be positive")
            if self.rate_limit.window_size <= 0:
                errors.append("Rate limit window_size must be positive")
        
        if errors:
            raise ResourceValidationError(f"Resource validation failed: {'; '.join(errors)}")
    
    def _validate_path(self, path: str) -> bool:
        """Validate resource path format."""
        # Path should start with / and contain valid characters
        if not path.startswith('/'):
            return False
        
        # Allow alphanumeric, hyphens, underscores, slashes, and path parameters
        path_pattern = re.compile(r'^/[a-zA-Z0-9/_\-{}]*$')
        return bool(path_pattern.match(path))
    
    def update_timestamp(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = get_current_time()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the resource."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.update_timestamp()
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the resource."""
        if tag in self.tags:
            self.tags.remove(tag)
            self.update_timestamp()
    
    def has_tag(self, tag: str) -> bool:
        """Check if resource has a specific tag."""
        return tag in self.tags
    
    def set_metadata(self, key: str, value: str) -> None:
        """Set metadata value."""
        self.metadata[key] = value
        self.update_timestamp()
    
    def get_metadata(self, key: str, default: str = "") -> str:
        """Get metadata value."""
        return self.metadata.get(key, default)
    
    def has_metadata(self, key: str) -> bool:
        """Check if metadata key exists."""
        return key in self.metadata
    
    def is_accessible_by(self, user_scopes: Set[str]) -> bool:
        """Check if resource is accessible by user with given scopes."""
        if self.access_level == AccessLevel.PUBLIC:
            return True
        
        if not self.scopes:
            return True
        
        # Check if user has any required scope
        return bool(user_scopes.intersection(set(self.scopes)))
    
    def is_available(self) -> bool:
        """Check if resource is currently available."""
        return self.status in {ResourceStatus.ACTIVE}
    
    def is_deprecated(self) -> bool:
        """Check if resource is deprecated."""
        return self.status == ResourceStatus.DEPRECATED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "status": self.status.value,
            "owner_id": self.owner_id,
            "access_level": self.access_level.value,
            "scopes": self.scopes,
            "path": self.path,
            "methods": self.methods,
            "region": self.region,
            "environment": self.environment,
            "rate_limit": self.rate_limit.to_dict() if self.rate_limit else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata,
            "config": self.config.to_dict()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Resource':
        """Create resource from dictionary."""
        # Parse timestamps
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = get_current_time()
        
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        elif updated_at is None:
            updated_at = get_current_time()
        
        # Parse rate limit
        rate_limit_data = data.get("rate_limit")
        rate_limit = None
        if rate_limit_data:
            rate_limit = RateLimit.from_dict(rate_limit_data)
        
        # Parse config
        config_data = data.get("config", {})
        config = ResourceConfig.from_dict(config_data)
        
        return cls(
            id=data["id"],
            type=ResourceType(data["type"]),
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            status=ResourceStatus(data.get("status", "active")),
            owner_id=data.get("owner_id", ""),
            access_level=AccessLevel(data.get("access_level", "protected")),
            scopes=data.get("scopes", []),
            path=data.get("path", ""),
            methods=data.get("methods", ["GET"]),
            region=data.get("region", "default"),
            environment=data.get("environment", "production"),
            rate_limit=rate_limit,
            created_at=created_at,
            updated_at=updated_at,
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
            config=config
        )


def create_resource(resource_id: str = None,
                   resource_type: Union[ResourceType, str] = ResourceType.API,
                   name: str = "",
                   **kwargs) -> Resource:
    """
    Create a new resource with default values.
    
    Args:
        resource_id: Resource ID (generated if not provided)
        resource_type: Type of resource
        name: Resource name
        **kwargs: Additional resource properties
    
    Returns:
        Resource instance
    """
    if resource_id is None:
        resource_id = generate_id()
    
    if isinstance(resource_type, str):
        resource_type = ResourceType(resource_type)
    
    if not name:
        name = f"{resource_type.value}_{resource_id[:8]}"
    
    resource = Resource(
        id=resource_id,
        type=resource_type,
        name=name,
        **kwargs
    )
    
    resource.validate()
    return resource


def create_api_resource(api_id: str = None,
                       name: str = "",
                       path: str = "",
                       methods: List[str] = None,
                       **kwargs) -> Resource:
    """Create an API resource."""
    if methods is None:
        methods = ["GET", "POST"]
    
    return create_resource(
        resource_id=api_id,
        resource_type=ResourceType.API,
        name=name,
        path=path,
        methods=methods,
        **kwargs
    )


def create_service_resource(service_id: str = None,
                           name: str = "",
                           **kwargs) -> Resource:
    """Create a service resource."""
    return create_resource(
        resource_id=service_id,
        resource_type=ResourceType.SERVICE,
        name=name,
        **kwargs
    )


def create_data_resource(data_id: str = None,
                        name: str = "",
                        access_level: Union[AccessLevel, str] = AccessLevel.PRIVATE,
                        **kwargs) -> Resource:
    """Create a data resource."""
    if isinstance(access_level, str):
        access_level = AccessLevel(access_level)
    
    return create_resource(
        resource_id=data_id,
        resource_type=ResourceType.DATA,
        name=name,
        access_level=access_level,
        **kwargs
    )