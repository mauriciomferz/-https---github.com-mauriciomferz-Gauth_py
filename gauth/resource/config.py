"""
Resource configuration and lifecycle management for GAuth.

This module provides configuration validation, lifecycle management,
and resource definition utilities.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable, Union, Type
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from .types import (
    Resource, ResourceType, ResourceStatus, AccessLevel,
    ResourceConfig, RateLimit, ResourceError, ResourceValidationError
)
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class LifecycleEvent(Enum):
    """Resource lifecycle events."""
    
    CREATED = "created"
    ACTIVATED = "activated"
    DEPRECATED = "deprecated"
    DELETED = "deleted"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    ERROR = "error"


@dataclass
class LifecycleHook:
    """Resource lifecycle hook configuration."""
    
    event: LifecycleEvent
    callback: Callable[[Resource, Dict[str, Any]], None]
    conditions: Optional[Dict[str, Any]] = None
    async_callback: bool = False


class ResourceValidator(ABC):
    """Abstract base class for resource validators."""
    
    @abstractmethod
    def validate(self, resource: Resource) -> None:
        """
        Validate a resource.
        
        Args:
            resource: Resource to validate
            
        Raises:
            ResourceValidationError: If validation fails
        """
        pass


class ScopeValidator(ResourceValidator):
    """Validates resource scopes."""
    
    def __init__(self, allowed_scopes: List[str]):
        """
        Initialize scope validator.
        
        Args:
            allowed_scopes: List of allowed scope patterns
        """
        self.allowed_scopes = allowed_scopes
    
    def validate(self, resource: Resource) -> None:
        """Validate resource scopes."""
        for scope in resource.scopes:
            if not any(self._matches_pattern(scope, pattern) for pattern in self.allowed_scopes):
                raise ResourceValidationError(f"Invalid scope: {scope}")
    
    def _matches_pattern(self, scope: str, pattern: str) -> bool:
        """Check if scope matches pattern."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return scope.startswith(pattern[:-1])
        return scope == pattern


class NameValidator(ResourceValidator):
    """Validates resource names."""
    
    def __init__(self, min_length: int = 3, max_length: int = 100,
                 allowed_chars: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"):
        """
        Initialize name validator.
        
        Args:
            min_length: Minimum name length
            max_length: Maximum name length
            allowed_chars: Allowed characters in name
        """
        self.min_length = min_length
        self.max_length = max_length
        self.allowed_chars = set(allowed_chars)
    
    def validate(self, resource: Resource) -> None:
        """Validate resource name."""
        name = resource.name
        
        if len(name) < self.min_length:
            raise ResourceValidationError(f"Name too short: {len(name)} < {self.min_length}")
        
        if len(name) > self.max_length:
            raise ResourceValidationError(f"Name too long: {len(name)} > {self.max_length}")
        
        invalid_chars = set(name) - self.allowed_chars
        if invalid_chars:
            raise ResourceValidationError(f"Invalid characters in name: {invalid_chars}")


class ConfigValidator(ResourceValidator):
    """Validates resource configuration."""
    
    def __init__(self, required_keys: List[str] = None,
                 allowed_keys: List[str] = None):
        """
        Initialize config validator.
        
        Args:
            required_keys: Required configuration keys
            allowed_keys: Allowed configuration keys
        """
        self.required_keys = required_keys or []
        self.allowed_keys = allowed_keys
    
    def validate(self, resource: Resource) -> None:
        """Validate resource configuration."""
        if not resource.config:
            if self.required_keys:
                raise ResourceValidationError("Configuration is required")
            return
        
        config_keys = set(resource.config.get_all_keys())
        
        # Check required keys
        missing_keys = set(self.required_keys) - config_keys
        if missing_keys:
            raise ResourceValidationError(f"Missing required config keys: {missing_keys}")
        
        # Check allowed keys
        if self.allowed_keys:
            invalid_keys = config_keys - set(self.allowed_keys)
            if invalid_keys:
                raise ResourceValidationError(f"Invalid config keys: {invalid_keys}")


class ResourceTemplate:
    """Template for creating resources with predefined settings."""
    
    def __init__(self,
                 name: str,
                 resource_type: ResourceType,
                 description: str = "",
                 default_access_level: AccessLevel = AccessLevel.PROTECTED,
                 default_scopes: List[str] = None,
                 default_config: Dict[str, Any] = None,
                 default_tags: List[str] = None,
                 validators: List[ResourceValidator] = None):
        """
        Initialize resource template.
        
        Args:
            name: Template name
            resource_type: Resource type
            description: Template description
            default_access_level: Default access level
            default_scopes: Default scopes
            default_config: Default configuration
            default_tags: Default tags
            validators: Custom validators
        """
        self.name = name
        self.resource_type = resource_type
        self.description = description
        self.default_access_level = default_access_level
        self.default_scopes = default_scopes or []
        self.default_config = default_config or {}
        self.default_tags = default_tags or []
        self.validators = validators or []
    
    def create_resource(self,
                       resource_name: str,
                       owner_id: str,
                       **overrides) -> Resource:
        """
        Create a resource from template.
        
        Args:
            resource_name: Resource name
            owner_id: Resource owner ID
            **overrides: Override default values
            
        Returns:
            Created resource
        """
        # Merge defaults with overrides
        config_data = {**self.default_config, **overrides.get('config', {})}
        config = ResourceConfig()
        for key, value in config_data.items():
            config.set(key, value)
        
        resource = Resource(
            name=resource_name,
            type=self.resource_type,
            description=overrides.get('description', self.description),
            owner_id=owner_id,
            access_level=overrides.get('access_level', self.default_access_level),
            scopes=overrides.get('scopes', self.default_scopes.copy()),
            path=overrides.get('path', f"/{self.resource_type.value}/{resource_name}"),
            methods=overrides.get('methods', ["GET"]),
            region=overrides.get('region', "default"),
            environment=overrides.get('environment', "production"),
            tags=overrides.get('tags', self.default_tags.copy()),
            config=config
        )
        
        # Validate with template validators
        for validator in self.validators:
            validator.validate(resource)
        
        return resource


class LifecycleManager:
    """Manages resource lifecycle events and hooks."""
    
    def __init__(self):
        """Initialize lifecycle manager."""
        self.hooks: Dict[LifecycleEvent, List[LifecycleHook]] = {
            event: [] for event in LifecycleEvent
        }
        self.event_history: List[Dict[str, Any]] = []
        self.max_history = 1000
    
    def add_hook(self, hook: LifecycleHook) -> None:
        """Add a lifecycle hook."""
        self.hooks[hook.event].append(hook)
    
    def remove_hook(self, hook: LifecycleHook) -> None:
        """Remove a lifecycle hook."""
        if hook in self.hooks[hook.event]:
            self.hooks[hook.event].remove(hook)
    
    async def trigger_event(self, event: LifecycleEvent, resource: Resource,
                           context: Dict[str, Any] = None) -> None:
        """
        Trigger a lifecycle event.
        
        Args:
            event: Lifecycle event
            resource: Resource
            context: Additional context
        """
        context = context or {}
        
        # Record event in history
        self._record_event(event, resource, context)
        
        # Execute hooks
        for hook in self.hooks[event]:
            if self._should_execute_hook(hook, resource, context):
                try:
                    if hook.async_callback:
                        await hook.callback(resource, context)
                    else:
                        hook.callback(resource, context)
                except Exception as e:
                    logger.error(f"Hook execution error for {event}: {e}")
    
    def _should_execute_hook(self, hook: LifecycleHook, resource: Resource,
                           context: Dict[str, Any]) -> bool:
        """Check if hook should be executed based on conditions."""
        if not hook.conditions:
            return True
        
        for key, expected_value in hook.conditions.items():
            if key == "resource_type":
                if resource.type != expected_value:
                    return False
            elif key == "access_level":
                if resource.access_level != expected_value:
                    return False
            elif key == "owner_id":
                if resource.owner_id != expected_value:
                    return False
            elif key in context:
                if context[key] != expected_value:
                    return False
        
        return True
    
    def _record_event(self, event: LifecycleEvent, resource: Resource,
                     context: Dict[str, Any]) -> None:
        """Record event in history."""
        event_record = {
            "timestamp": get_current_time(),
            "event": event.value,
            "resource_id": resource.id,
            "resource_type": resource.type.value,
            "context": context
        }
        
        self.event_history.append(event_record)
        
        # Trim history if needed
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]
    
    def get_resource_history(self, resource_id: str) -> List[Dict[str, Any]]:
        """Get event history for a resource."""
        return [
            event for event in self.event_history
            if event["resource_id"] == resource_id
        ]
    
    def get_event_history(self, event: LifecycleEvent,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """Get history for a specific event type."""
        events = [
            event_record for event_record in self.event_history
            if event_record["event"] == event.value
        ]
        return events[-limit:]


# Predefined templates
API_RESOURCE_TEMPLATE = ResourceTemplate(
    name="api_resource",
    resource_type=ResourceType.API,
    description="Standard API resource",
    default_access_level=AccessLevel.PROTECTED,
    default_scopes=["api:read", "api:write"],
    default_config={
        "rate_limit_rpm": 1000,
        "timeout": 30,
        "retry_count": 3
    },
    default_tags=["api", "service"],
    validators=[
        NameValidator(min_length=3, max_length=50),
        ScopeValidator(["api:*", "service:*"]),
        ConfigValidator(required_keys=["rate_limit_rpm"])
    ]
)

SERVICE_RESOURCE_TEMPLATE = ResourceTemplate(
    name="service_resource",
    resource_type=ResourceType.SERVICE,
    description="Standard service resource",
    default_access_level=AccessLevel.PRIVATE,
    default_scopes=["service:invoke"],
    default_config={
        "health_check_interval": 30,
        "max_instances": 10,
        "scaling_enabled": True
    },
    default_tags=["service", "microservice"],
    validators=[
        NameValidator(min_length=3, max_length=100),
        ScopeValidator(["service:*"]),
        ConfigValidator(required_keys=["health_check_interval"])
    ]
)

DATA_RESOURCE_TEMPLATE = ResourceTemplate(
    name="data_resource",
    resource_type=ResourceType.DATA,
    description="Standard data resource",
    default_access_level=AccessLevel.RESTRICTED,
    default_scopes=["data:read"],
    default_config={
        "encryption_enabled": True,
        "backup_enabled": True,
        "retention_days": 90
    },
    default_tags=["data", "storage"],
    validators=[
        NameValidator(min_length=3, max_length=200),
        ScopeValidator(["data:*"]),
        ConfigValidator(required_keys=["encryption_enabled"])
    ]
)


def create_lifecycle_manager() -> LifecycleManager:
    """Create a lifecycle manager with default hooks."""
    manager = LifecycleManager()
    
    # Add default logging hooks
    def log_hook(resource: Resource, context: Dict[str, Any]) -> None:
        event = context.get('event', 'unknown')
        logger.info(f"Resource {resource.id} {event}")
    
    for event in LifecycleEvent:
        manager.add_hook(LifecycleHook(
            event=event,
            callback=log_hook,
            async_callback=False
        ))
    
    return manager


def get_predefined_templates() -> Dict[str, ResourceTemplate]:
    """Get predefined resource templates."""
    return {
        "api": API_RESOURCE_TEMPLATE,
        "service": SERVICE_RESOURCE_TEMPLATE,
        "data": DATA_RESOURCE_TEMPLATE
    }