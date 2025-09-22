"""
Distributed token storage implementation for GAuth.

This module provides Redis-based distributed token storage
suitable for production deployments with multiple instances.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import asdict

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

from .store import TokenStore, TokenData, get_current_time
from .memory import MemoryTokenStore


logger = logging.getLogger(__name__)


class DistributedConfig:
    """Configuration for distributed token storage."""
    
    def __init__(self,
                 addresses: List[str] = None,
                 password: Optional[str] = None,
                 db: int = 0,
                 ssl: bool = False,
                 ssl_cert_reqs: str = "required",
                 connection_pool_kwargs: Dict[str, Any] = None,
                 key_prefix: str = "gauth:token:",
                 cleanup_batch_size: int = 100):
        """
        Initialize distributed configuration.
        
        Args:
            addresses: List of Redis addresses (host:port)
            password: Redis password
            db: Redis database number
            ssl: Enable SSL connection
            ssl_cert_reqs: SSL certificate requirements
            connection_pool_kwargs: Additional connection pool arguments
            key_prefix: Prefix for Redis keys
            cleanup_batch_size: Batch size for cleanup operations
        """
        self.addresses = addresses or ["localhost:6379"]
        self.password = password
        self.db = db
        self.ssl = ssl
        self.ssl_cert_reqs = ssl_cert_reqs
        self.connection_pool_kwargs = connection_pool_kwargs or {}
        self.key_prefix = key_prefix
        self.cleanup_batch_size = cleanup_batch_size


class DistributedTokenStore(TokenStore):
    """
    Redis-based distributed token store implementation.
    
    This implementation uses Redis for distributed token storage
    with support for clustering and high availability.
    """
    
    def __init__(self, config: DistributedConfig):
        """
        Initialize distributed token store.
        
        Args:
            config: Distributed configuration
        """
        if not REDIS_AVAILABLE:
            raise ImportError("redis package is required for DistributedTokenStore")
        
        self.config = config
        self._redis: Optional[redis.Redis] = None
        self._lock = asyncio.Lock()
        self._connected = False
        
        # Fallback to memory store if Redis is unavailable
        self._fallback_store = MemoryTokenStore()
        self._using_fallback = False
    
    async def connect(self) -> None:
        """Connect to Redis."""
        if self._connected:
            return
        
        try:
            # Parse first address for initial connection
            host, port = self.config.addresses[0].split(":")
            port = int(port)
            
            # Create Redis connection
            self._redis = redis.Redis(
                host=host,
                port=port,
                password=self.config.password,
                db=self.config.db,
                ssl=self.config.ssl,
                ssl_cert_reqs=self.config.ssl_cert_reqs,
                decode_responses=True,
                **self.config.connection_pool_kwargs
            )
            
            # Test connection
            await self._redis.ping()
            self._connected = True
            self._using_fallback = False
            
            logger.info(f"Connected to Redis at {host}:{port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            logger.warning("Falling back to memory store")
            
            self._using_fallback = True
            await self._fallback_store.start()
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._connected = False
            logger.info("Disconnected from Redis")
        
        if self._using_fallback:
            await self._fallback_store.stop()
    
    def _get_key(self, token: str) -> str:
        """Get Redis key for token."""
        return f"{self.config.key_prefix}{token}"
    
    def _get_client_key(self, client_id: str) -> str:
        """Get Redis key for client tokens."""
        return f"{self.config.key_prefix}client:{client_id}"
    
    def _get_owner_key(self, owner_id: str) -> str:
        """Get Redis key for owner tokens."""
        return f"{self.config.key_prefix}owner:{owner_id}"
    
    async def _ensure_connected(self) -> None:
        """Ensure Redis connection is established."""
        if not self._connected and not self._using_fallback:
            await self.connect()
    
    async def store(self, token: str, data: TokenData) -> None:
        """Store a token with its associated data."""
        await self._ensure_connected()
        
        if self._using_fallback:
            await self._fallback_store.store(token, data)
            return
        
        try:
            key = self._get_key(token)
            value = data.to_json()
            
            # Calculate TTL based on token expiration
            ttl = int(data.time_until_expiry().total_seconds())
            if ttl <= 0:
                # Token already expired, don't store
                return
            
            # Store token data
            await self._redis.setex(key, ttl, value)
            
            # Add to client and owner indexes
            client_key = self._get_client_key(data.client_id)
            owner_key = self._get_owner_key(data.owner_id)
            
            await self._redis.sadd(client_key, token)
            await self._redis.sadd(owner_key, token)
            
            # Set expiration for indexes (slightly longer than token)
            await self._redis.expire(client_key, ttl + 60)
            await self._redis.expire(owner_key, ttl + 60)
            
            logger.debug(f"Stored token for client {data.client_id}")
            
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            raise
    
    async def get(self, token: str) -> Optional[TokenData]:
        """Retrieve token data for a given token."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.get(token)
        
        try:
            key = self._get_key(token)
            value = await self._redis.get(key)
            
            if value:
                data = TokenData.from_json(value)
                
                # Double-check expiration
                if data.is_expired():
                    await self.delete(token)
                    return None
                
                return data
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get token: {e}")
            return None
    
    async def delete(self, token: str) -> bool:
        """Remove a token from the store."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.delete(token)
        
        try:
            # Get token data first to clean up indexes
            data = await self.get(token)
            
            key = self._get_key(token)
            result = await self._redis.delete(key)
            
            if data and result > 0:
                # Remove from indexes
                client_key = self._get_client_key(data.client_id)
                owner_key = self._get_owner_key(data.owner_id)
                
                await self._redis.srem(client_key, token)
                await self._redis.srem(owner_key, token)
                
                logger.debug(f"Deleted token for client {data.client_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete token: {e}")
            return False
    
    async def cleanup(self) -> int:
        """Remove expired tokens from the store."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.cleanup()
        
        try:
            # Redis automatically expires keys, but we need to clean up indexes
            cleaned_count = 0
            
            # Get all token keys
            pattern = f"{self.config.key_prefix}*"
            cursor = 0
            
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor,
                    match=pattern,
                    count=self.config.cleanup_batch_size
                )
                
                if not keys:
                    break
                
                # Filter token keys (not index keys)
                token_keys = [k for k in keys if not k.endswith(":") and "client:" not in k and "owner:" not in k]
                
                for key in token_keys:
                    # Check if key still exists (might have expired)
                    if not await self._redis.exists(key):
                        cleaned_count += 1
                
                if cursor == 0:
                    break
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired tokens")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup tokens: {e}")
            return 0
    
    async def get_tokens_by_client(self, client_id: str) -> List[Tuple[str, TokenData]]:
        """Get all tokens for a client."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.get_tokens_by_client(client_id)
        
        try:
            client_key = self._get_client_key(client_id)
            token_set = await self._redis.smembers(client_key)
            
            tokens = []
            for token in token_set:
                data = await self.get(token)
                if data:
                    tokens.append((token, data))
            
            return tokens
            
        except Exception as e:
            logger.error(f"Failed to get tokens by client: {e}")
            return []
    
    async def get_tokens_by_owner(self, owner_id: str) -> List[Tuple[str, TokenData]]:
        """Get all tokens for an owner."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.get_tokens_by_owner(owner_id)
        
        try:
            owner_key = self._get_owner_key(owner_id)
            token_set = await self._redis.smembers(owner_key)
            
            tokens = []
            for token in token_set:
                data = await self.get(token)
                if data:
                    tokens.append((token, data))
            
            return tokens
            
        except Exception as e:
            logger.error(f"Failed to get tokens by owner: {e}")
            return []
    
    async def count_tokens(self) -> int:
        """Count total number of tokens."""
        await self._ensure_connected()
        
        if self._using_fallback:
            return await self._fallback_store.count_tokens()
        
        try:
            pattern = f"{self.config.key_prefix}*"
            cursor = 0
            count = 0
            
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor,
                    match=pattern,
                    count=1000
                )
                
                # Filter token keys (not index keys)
                token_keys = [k for k in keys if not k.endswith(":") and "client:" not in k and "owner:" not in k]
                count += len(token_keys)
                
                if cursor == 0:
                    break
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to count tokens: {e}")
            return 0
    
    async def count_valid_tokens(self) -> int:
        """Count number of valid tokens."""
        # For Redis, all stored tokens should be valid (expired ones are auto-removed)
        return await self.count_tokens()
    
    async def close(self) -> None:
        """Close the distributed store and clean up resources."""
        await self.disconnect()


def create_distributed_store(addresses: List[str] = None,
                           password: Optional[str] = None,
                           db: int = 0,
                           **kwargs) -> DistributedTokenStore:
    """
    Create a distributed token store.
    
    Args:
        addresses: List of Redis addresses
        password: Redis password
        db: Redis database number
        **kwargs: Additional configuration options
        
    Returns:
        DistributedTokenStore instance
    """
    config = DistributedConfig(
        addresses=addresses,
        password=password,
        db=db,
        **kwargs
    )
    
    return DistributedTokenStore(config)