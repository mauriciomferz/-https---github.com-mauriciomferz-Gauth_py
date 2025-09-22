"""
Resource manager for GAuth.

This module provides comprehensive resource management including
CRUD operations, validation, lifecycle management, and persistence.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Any, Callable, Union
from datetime import datetime, timedelta
import os
import pickle
from pathlib import Path

from .types import (
    Resource, ResourceType, ResourceStatus, AccessLevel,
    ResourceError, ResourceNotFoundError, ResourceValidationError,
    create_resource
)
from ..common.utils import get_current_time, generate_id


logger = logging.getLogger(__name__)


class ResourceStore(ABC):
    """Abstract base class for resource storage backends."""
    
    @abstractmethod
    async def create(self, resource: Resource) -> Resource:
        """Create a new resource."""
        pass
    
    @abstractmethod
    async def get(self, resource_id: str) -> Optional[Resource]:
        """Get a resource by ID."""
        pass
    
    @abstractmethod
    async def update(self, resource: Resource) -> Resource:
        """Update an existing resource."""
        pass
    
    @abstractmethod
    async def delete(self, resource_id: str) -> bool:
        """Delete a resource."""
        pass
    
    @abstractmethod
    async def list(self, 
                  resource_type: Optional[ResourceType] = None,
                  status: Optional[ResourceStatus] = None,
                  owner_id: Optional[str] = None,
                  tags: Optional[List[str]] = None,
                  limit: int = 100,
                  offset: int = 0) -> List[Resource]:
        """List resources with optional filtering."""
        pass
    
    @abstractmethod
    async def search(self, query: str, limit: int = 100) -> List[Resource]:
        """Search resources by query."""
        pass
    
    @abstractmethod
    async def count(self, 
                   resource_type: Optional[ResourceType] = None,
                   status: Optional[ResourceStatus] = None) -> int:
        """Count resources with optional filtering."""
        pass


class InMemoryResourceStore(ResourceStore):
    """In-memory resource store implementation."""
    
    def __init__(self):
        """Initialize in-memory store."""
        self._resources: Dict[str, Resource] = {}
        self._lock = asyncio.Lock()
    
    async def create(self, resource: Resource) -> Resource:
        """Create a new resource."""
        async with self._lock:
            if resource.id in self._resources:
                raise ResourceError(f"Resource {resource.id} already exists")
            
            resource.validate()
            resource.created_at = get_current_time()
            resource.updated_at = resource.created_at
            
            self._resources[resource.id] = resource
            logger.info(f"Created resource: {resource.id}")
            return resource
    
    async def get(self, resource_id: str) -> Optional[Resource]:
        """Get a resource by ID."""
        async with self._lock:
            return self._resources.get(resource_id)
    
    async def update(self, resource: Resource) -> Resource:
        """Update an existing resource."""
        async with self._lock:
            if resource.id not in self._resources:
                raise ResourceNotFoundError(f"Resource {resource.id} not found")
            
            resource.validate()
            resource.update_timestamp()
            
            self._resources[resource.id] = resource
            logger.info(f"Updated resource: {resource.id}")
            return resource
    
    async def delete(self, resource_id: str) -> bool:
        """Delete a resource."""
        async with self._lock:
            if resource_id in self._resources:
                del self._resources[resource_id]
                logger.info(f"Deleted resource: {resource_id}")
                return True
            return False
    
    async def list(self, 
                  resource_type: Optional[ResourceType] = None,
                  status: Optional[ResourceStatus] = None,
                  owner_id: Optional[str] = None,
                  tags: Optional[List[str]] = None,
                  limit: int = 100,
                  offset: int = 0) -> List[Resource]:
        """List resources with optional filtering."""
        async with self._lock:
            resources = list(self._resources.values())
            
            # Apply filters
            if resource_type:
                resources = [r for r in resources if r.type == resource_type]
            
            if status:
                resources = [r for r in resources if r.status == status]
            
            if owner_id:
                resources = [r for r in resources if r.owner_id == owner_id]
            
            if tags:
                tag_set = set(tags)
                resources = [r for r in resources if tag_set.intersection(set(r.tags))]
            
            # Sort by creation date (newest first)
            resources.sort(key=lambda r: r.created_at, reverse=True)
            
            # Apply pagination
            return resources[offset:offset + limit]
    
    async def search(self, query: str, limit: int = 100) -> List[Resource]:
        """Search resources by query."""
        async with self._lock:
            query_lower = query.lower()
            matches = []
            
            for resource in self._resources.values():
                # Search in name, description, and tags
                if (query_lower in resource.name.lower() or
                    query_lower in resource.description.lower() or
                    any(query_lower in tag.lower() for tag in resource.tags)):
                    matches.append(resource)
            
            # Sort by relevance (name matches first)
            matches.sort(key=lambda r: (
                query_lower not in r.name.lower(),
                r.created_at
            ), reverse=True)
            
            return matches[:limit]
    
    async def count(self, 
                   resource_type: Optional[ResourceType] = None,
                   status: Optional[ResourceStatus] = None) -> int:
        """Count resources with optional filtering."""
        async with self._lock:
            resources = list(self._resources.values())
            
            if resource_type:
                resources = [r for r in resources if r.type == resource_type]
            
            if status:
                resources = [r for r in resources if r.status == status]
            
            return len(resources)


class FileResourceStore(ResourceStore):
    """File-based resource store implementation."""
    
    def __init__(self, storage_path: str = "resources"):
        """
        Initialize file store.
        
        Args:
            storage_path: Directory path for storing resources
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
    
    def _get_resource_file(self, resource_id: str) -> Path:
        """Get file path for resource."""
        return self.storage_path / f"{resource_id}.json"
    
    async def create(self, resource: Resource) -> Resource:
        """Create a new resource."""
        async with self._lock:
            resource_file = self._get_resource_file(resource.id)
            
            if resource_file.exists():
                raise ResourceError(f"Resource {resource.id} already exists")
            
            resource.validate()
            resource.created_at = get_current_time()
            resource.updated_at = resource.created_at
            
            # Save to file
            with open(resource_file, 'w') as f:
                json.dump(resource.to_dict(), f, indent=2)
            
            logger.info(f"Created resource: {resource.id}")
            return resource
    
    async def get(self, resource_id: str) -> Optional[Resource]:
        """Get a resource by ID."""
        async with self._lock:
            resource_file = self._get_resource_file(resource_id)
            
            if not resource_file.exists():
                return None
            
            try:
                with open(resource_file, 'r') as f:
                    data = json.load(f)
                return Resource.from_dict(data)
            except Exception as e:
                logger.error(f"Error loading resource {resource_id}: {e}")
                return None
    
    async def update(self, resource: Resource) -> Resource:
        """Update an existing resource."""
        async with self._lock:
            resource_file = self._get_resource_file(resource.id)
            
            if not resource_file.exists():
                raise ResourceNotFoundError(f"Resource {resource.id} not found")
            
            resource.validate()
            resource.update_timestamp()
            
            # Save to file
            with open(resource_file, 'w') as f:
                json.dump(resource.to_dict(), f, indent=2)
            
            logger.info(f"Updated resource: {resource.id}")
            return resource
    
    async def delete(self, resource_id: str) -> bool:
        """Delete a resource."""
        async with self._lock:
            resource_file = self._get_resource_file(resource_id)
            
            if resource_file.exists():
                resource_file.unlink()
                logger.info(f"Deleted resource: {resource_id}")
                return True
            return False
    
    async def list(self, 
                  resource_type: Optional[ResourceType] = None,
                  status: Optional[ResourceStatus] = None,
                  owner_id: Optional[str] = None,
                  tags: Optional[List[str]] = None,
                  limit: int = 100,
                  offset: int = 0) -> List[Resource]:
        """List resources with optional filtering."""
        async with self._lock:
            resources = []
            
            # Load all resources
            for resource_file in self.storage_path.glob("*.json"):
                try:
                    with open(resource_file, 'r') as f:
                        data = json.load(f)
                    resource = Resource.from_dict(data)
                    resources.append(resource)
                except Exception as e:
                    logger.error(f"Error loading resource from {resource_file}: {e}")
            
            # Apply filters
            if resource_type:
                resources = [r for r in resources if r.type == resource_type]
            
            if status:
                resources = [r for r in resources if r.status == status]
            
            if owner_id:
                resources = [r for r in resources if r.owner_id == owner_id]
            
            if tags:
                tag_set = set(tags)
                resources = [r for r in resources if tag_set.intersection(set(r.tags))]
            
            # Sort by creation date (newest first)
            resources.sort(key=lambda r: r.created_at, reverse=True)
            
            # Apply pagination
            return resources[offset:offset + limit]
    
    async def search(self, query: str, limit: int = 100) -> List[Resource]:
        """Search resources by query."""
        async with self._lock:
            query_lower = query.lower()
            matches = []
            
            # Load and search all resources
            for resource_file in self.storage_path.glob("*.json"):
                try:
                    with open(resource_file, 'r') as f:
                        data = json.load(f)
                    resource = Resource.from_dict(data)
                    
                    # Search in name, description, and tags
                    if (query_lower in resource.name.lower() or
                        query_lower in resource.description.lower() or
                        any(query_lower in tag.lower() for tag in resource.tags)):
                        matches.append(resource)
                        
                except Exception as e:
                    logger.error(f"Error loading resource from {resource_file}: {e}")
            
            # Sort by relevance
            matches.sort(key=lambda r: (
                query_lower not in r.name.lower(),
                r.created_at
            ), reverse=True)
            
            return matches[:limit]
    
    async def count(self, 
                   resource_type: Optional[ResourceType] = None,
                   status: Optional[ResourceStatus] = None) -> int:
        """Count resources with optional filtering."""
        resources = await self.list(resource_type=resource_type, status=status, limit=10000)
        return len(resources)


class ResourceManager:
    """Comprehensive resource manager."""
    
    def __init__(self, 
                 store: ResourceStore = None,
                 validators: List[Callable[[Resource], None]] = None,
                 hooks: Dict[str, List[Callable]] = None):
        """
        Initialize resource manager.
        
        Args:
            store: Resource storage backend
            validators: Additional resource validators
            hooks: Event hooks for resource operations
        """
        self.store = store or InMemoryResourceStore()
        self.validators = validators or []
        self.hooks = hooks or {}
        
        # Add default hooks
        for event in ['before_create', 'after_create', 'before_update', 
                     'after_update', 'before_delete', 'after_delete']:
            if event not in self.hooks:
                self.hooks[event] = []
    
    async def _run_hooks(self, event: str, resource: Resource = None, **kwargs) -> None:
        """Run event hooks."""
        for hook in self.hooks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook(resource, **kwargs)
                else:
                    hook(resource, **kwargs)
            except Exception as e:
                logger.error(f"Hook error for {event}: {e}")
    
    def _validate_resource(self, resource: Resource) -> None:
        """Run all validators on resource."""
        # Run built-in validation
        resource.validate()
        
        # Run custom validators
        for validator in self.validators:
            validator(resource)
    
    async def create_resource(self, resource: Resource) -> Resource:
        """Create a new resource."""
        try:
            await self._run_hooks('before_create', resource)
            
            self._validate_resource(resource)
            result = await self.store.create(resource)
            
            await self._run_hooks('after_create', result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to create resource {resource.id}: {e}")
            raise
    
    async def get_resource(self, resource_id: str) -> Optional[Resource]:
        """Get a resource by ID."""
        try:
            return await self.store.get(resource_id)
        except Exception as e:
            logger.error(f"Failed to get resource {resource_id}: {e}")
            return None
    
    async def update_resource(self, resource: Resource) -> Resource:
        """Update an existing resource."""
        try:
            await self._run_hooks('before_update', resource)
            
            self._validate_resource(resource)
            result = await self.store.update(resource)
            
            await self._run_hooks('after_update', result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to update resource {resource.id}: {e}")
            raise
    
    async def delete_resource(self, resource_id: str) -> bool:
        """Delete a resource."""
        try:
            resource = await self.get_resource(resource_id)
            if resource:
                await self._run_hooks('before_delete', resource)
                
                result = await self.store.delete(resource_id)
                
                if result:
                    await self._run_hooks('after_delete', resource)
                
                return result
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete resource {resource_id}: {e}")
            return False
    
    async def list_resources(self, **kwargs) -> List[Resource]:
        """List resources with filtering."""
        try:
            return await self.store.list(**kwargs)
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            return []
    
    async def search_resources(self, query: str, limit: int = 100) -> List[Resource]:
        """Search resources."""
        try:
            return await self.store.search(query, limit)
        except Exception as e:
            logger.error(f"Failed to search resources: {e}")
            return []
    
    async def count_resources(self, **kwargs) -> int:
        """Count resources."""
        try:
            return await self.store.count(**kwargs)
        except Exception as e:
            logger.error(f"Failed to count resources: {e}")
            return 0
    
    async def get_resources_by_owner(self, owner_id: str) -> List[Resource]:
        """Get all resources owned by a user."""
        return await self.list_resources(owner_id=owner_id)
    
    async def get_resources_by_type(self, resource_type: ResourceType) -> List[Resource]:
        """Get all resources of a specific type."""
        return await self.list_resources(resource_type=resource_type)
    
    async def get_active_resources(self) -> List[Resource]:
        """Get all active resources."""
        return await self.list_resources(status=ResourceStatus.ACTIVE)
    
    async def deprecate_resource(self, resource_id: str) -> Optional[Resource]:
        """Mark a resource as deprecated."""
        resource = await self.get_resource(resource_id)
        if resource:
            resource.status = ResourceStatus.DEPRECATED
            return await self.update_resource(resource)
        return None
    
    async def activate_resource(self, resource_id: str) -> Optional[Resource]:
        """Activate a resource."""
        resource = await self.get_resource(resource_id)
        if resource:
            resource.status = ResourceStatus.ACTIVE
            return await self.update_resource(resource)
        return None
    
    def add_validator(self, validator: Callable[[Resource], None]) -> None:
        """Add a custom validator."""
        self.validators.append(validator)
    
    def add_hook(self, event: str, hook: Callable) -> None:
        """Add an event hook."""
        if event not in self.hooks:
            self.hooks[event] = []
        self.hooks[event].append(hook)


def create_resource_manager(storage_type: str = "memory",
                           storage_path: str = "resources") -> ResourceManager:
    """
    Create a resource manager with specified storage backend.
    
    Args:
        storage_type: Storage backend type (memory, file)
        storage_path: Path for file storage
    
    Returns:
        ResourceManager instance
    """
    if storage_type == "file":
        store = FileResourceStore(storage_path)
    else:
        store = InMemoryResourceStore()
    
    return ResourceManager(store)