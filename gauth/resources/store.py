"""
Configuration storage implementations for resource management.
Provides different storage backends for service configurations.
"""

import json
import os
import asyncio
from abc import ABC
from pathlib import Path
from typing import Dict, List, Optional, AsyncIterator
import aiofiles
import logging

from .manager import ConfigStore
from .types import ServiceType, ServiceConfig

logger = logging.getLogger(__name__)


class FileConfigStore(ConfigStore):
    """File-based configuration store."""
    
    def __init__(self, storage_dir: str = "./configs"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._watchers: List[asyncio.Queue] = []
    
    def _get_config_path(self, service_type: ServiceType) -> Path:
        """Get the file path for a service configuration."""
        return self.storage_dir / f"{service_type.value}.json"
    
    async def load(self, service_type: ServiceType) -> Optional[ServiceConfig]:
        """Load service configuration from file."""
        config_path = self._get_config_path(service_type)
        
        if not config_path.exists():
            return None
        
        try:
            async with aiofiles.open(config_path, 'r') as f:
                data = json.loads(await f.read())
                return ServiceConfig.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load config for {service_type}: {e}")
            return None
    
    async def save(self, config: ServiceConfig) -> None:
        """Save service configuration to file."""
        config_path = self._get_config_path(config.type)
        
        try:
            data = config.to_dict()
            async with aiofiles.open(config_path, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
            # Notify watchers
            for watcher in self._watchers:
                try:
                    watcher.put_nowait(config)
                except asyncio.QueueFull:
                    logger.warning(f"Watcher queue full, dropping update for {config.type}")
        
        except Exception as e:
            logger.error(f"Failed to save config for {config.type}: {e}")
            raise
    
    async def list(self) -> List[ServiceConfig]:
        """List all service configurations."""
        configs = []
        
        for config_file in self.storage_dir.glob("*.json"):
            try:
                async with aiofiles.open(config_file, 'r') as f:
                    data = json.loads(await f.read())
                    config = ServiceConfig.from_dict(data)
                    configs.append(config)
            except Exception as e:
                logger.error(f"Failed to load config from {config_file}: {e}")
        
        return configs
    
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
        """Delete service configuration file."""
        config_path = self._get_config_path(service_type)
        
        if config_path.exists():
            try:
                config_path.unlink()
                return True
            except Exception as e:
                logger.error(f"Failed to delete config for {service_type}: {e}")
                return False
        
        return False


class DatabaseConfigStore(ConfigStore):
    """Database-based configuration store (placeholder implementation)."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self._watchers: List[asyncio.Queue] = []
        # In a real implementation, this would initialize database connection
    
    async def load(self, service_type: ServiceType) -> Optional[ServiceConfig]:
        """Load service configuration from database."""
        # Placeholder implementation
        # In reality, this would query the database
        logger.warning("DatabaseConfigStore.load not fully implemented")
        return None
    
    async def save(self, config: ServiceConfig) -> None:
        """Save service configuration to database."""
        # Placeholder implementation
        # In reality, this would insert/update in the database
        logger.warning("DatabaseConfigStore.save not fully implemented")
        
        # Notify watchers
        for watcher in self._watchers:
            try:
                watcher.put_nowait(config)
            except asyncio.QueueFull:
                logger.warning(f"Watcher queue full, dropping update for {config.type}")
    
    async def list(self) -> List[ServiceConfig]:
        """List all service configurations from database."""
        # Placeholder implementation
        logger.warning("DatabaseConfigStore.list not fully implemented")
        return []
    
    async def watch(self) -> AsyncIterator[ServiceConfig]:
        """Watch for configuration changes in database."""
        queue = asyncio.Queue(maxsize=100)
        self._watchers.append(queue)
        
        try:
            while True:
                config = await queue.get()
                yield config
        finally:
            self._watchers.remove(queue)
    
    async def delete(self, service_type: ServiceType) -> bool:
        """Delete service configuration from database."""
        # Placeholder implementation
        logger.warning("DatabaseConfigStore.delete not fully implemented")
        return False


# Utility functions for creating configured stores

def create_file_store(storage_dir: str = "./configs") -> FileConfigStore:
    """Create a file-based configuration store."""
    return FileConfigStore(storage_dir)


def create_database_store(connection_string: str) -> DatabaseConfigStore:
    """Create a database-based configuration store."""
    return DatabaseConfigStore(connection_string)


def create_memory_store() -> 'MemoryConfigStore':
    """Create an in-memory configuration store."""
    from .manager import MemoryConfigStore
    return MemoryConfigStore()