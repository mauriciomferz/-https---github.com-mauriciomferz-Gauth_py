"""
Token store package for GAuth.

This package provides comprehensive token storage functionality including
in-memory and distributed Redis-based storage implementations with
full lifecycle management and validation.
"""

from .store import (
    TokenData,
    TokenStatus,
    TokenStore,
    TokenStoreError,
    TokenNotFoundError,
    TokenExpiredError,
    TokenInvalidError,
    create_token_data,
    create_bearer_token,
    create_refresh_token
)

from .memory import (
    MemoryTokenStore,
    create_memory_store
)

from .distributed import (
    DistributedConfig,
    DistributedTokenStore,
    create_distributed_store,
    REDIS_AVAILABLE
)

# Optional direct Redis token store scaffold (lighter weight than full distributed wrapper)
try:  # pragma: no cover
    from .redis import RedisTokenStore  # type: ignore
except Exception:  # pragma: no cover
    RedisTokenStore = None  # type: ignore

__all__ = [
    # Core types and interfaces
    "TokenData",
    "TokenStatus",
    "TokenStore",
    "TokenStoreError",
    "TokenNotFoundError",
    "TokenExpiredError",
    "TokenInvalidError",
    "create_token_data",
    "create_bearer_token",
    "create_refresh_token",
    
    # Memory store
    "MemoryTokenStore",
    "create_memory_store",
    
    # Distributed store
    "DistributedConfig",
    "DistributedTokenStore",
    "create_distributed_store",
    "REDIS_AVAILABLE",
    # Optional direct Redis store
    "RedisTokenStore"
]

__version__ = "1.0.0"