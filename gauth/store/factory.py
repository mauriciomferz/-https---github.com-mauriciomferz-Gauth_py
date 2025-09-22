"""
Factory for creating storage implementations.
Provides a centralized way to create and configure storage backends.
"""

from typing import Dict, Any, Optional, Type
from dataclasses import dataclass
from .types import TokenStore
from .memory import MemoryTokenStore


@dataclass
class StorageConfig:
    """Configuration for storage backends."""
    store_type: str
    max_capacity: Optional[int] = None
    ttl_seconds: Optional[int] = None
    connection_url: Optional[str] = None
    pool_size: Optional[int] = None
    timeout_seconds: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'store_type': self.store_type,
            'max_capacity': self.max_capacity,
            'ttl_seconds': self.ttl_seconds,
            'connection_url': self.connection_url,
            'pool_size': self.pool_size,
            'timeout_seconds': self.timeout_seconds
        }


# Registry of available storage implementations
_STORAGE_IMPLEMENTATIONS: Dict[str, Type[TokenStore]] = {
    'memory': MemoryTokenStore,
}


class StorageFactory:
    """Factory for creating storage implementations."""
    
    @staticmethod
    def create_store(store_type: str, config: Optional[Dict[str, Any]] = None) -> TokenStore:
        """
        Create a token store instance.
        
        Args:
            store_type: Type of storage ('memory', 'redis', 'database', etc.)
            config: Configuration parameters for the storage backend
            
        Returns:
            TokenStore instance
            
        Raises:
            ValueError: If store_type is not supported
        """
        if config is None:
            config = {}
            
        implementation = _STORAGE_IMPLEMENTATIONS.get(store_type.lower())
        if not implementation:
            raise ValueError(f"Unsupported storage type: {store_type}")
        
        return implementation(**config)
    
    @staticmethod
    def register_implementation(name: str, implementation: Type[TokenStore]) -> None:
        """
        Register a new storage implementation.
        
        Args:
            name: Name to register the implementation under
            implementation: TokenStore implementation class
        """
        _STORAGE_IMPLEMENTATIONS[name.lower()] = implementation
    
    @staticmethod
    def get_available_types() -> list[str]:
        """Get list of available storage types."""
        return list(_STORAGE_IMPLEMENTATIONS.keys())


def create_memory_store(**kwargs) -> MemoryTokenStore:
    """Create a memory-based token store."""
    return MemoryTokenStore(**kwargs)


def create_store(store_type: str, config: Optional[Dict[str, Any]] = None) -> TokenStore:
    """
    Convenience function to create a token store.
    
    Args:
        store_type: Type of storage
        config: Configuration parameters
        
    Returns:
        TokenStore instance
    """
    return StorageFactory.create_store(store_type, config)


def create_token_store(config: StorageConfig) -> TokenStore:
    """
    Create a token store from configuration.
    
    Args:
        config: Storage configuration
        
    Returns:
        TokenStore instance
    """
    return StorageFactory.create_store(config.store_type, config.to_dict())