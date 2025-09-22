"""
Token storage implementation for GAuth.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import asyncio
from datetime import datetime

from ..core.types import AccessToken


class TokenStore(ABC):
    """Abstract base class for token storage"""

    @abstractmethod
    async def store(self, token: str, access_token: AccessToken) -> None:
        """Store a token"""
        pass

    @abstractmethod
    async def get(self, token: str) -> Optional[AccessToken]:
        """Retrieve a token"""
        pass

    @abstractmethod
    async def delete(self, token: str) -> bool:
        """Delete a token"""
        pass

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired tokens and return count of removed tokens"""
        pass

    async def close(self) -> None:
        """Close the token store and release resources"""
        pass


class MemoryTokenStore(TokenStore):
    """In-memory token store for development and testing"""

    def __init__(self):
        self.tokens: Dict[str, AccessToken] = {}
        self._lock = asyncio.Lock()

    async def store(self, token: str, access_token: AccessToken) -> None:
        """Store a token in memory"""
        async with self._lock:
            self.tokens[token] = access_token

    async def get(self, token: str) -> Optional[AccessToken]:
        """Retrieve a token from memory"""
        async with self._lock:
            return self.tokens.get(token)

    async def delete(self, token: str) -> bool:
        """Delete a token from memory"""
        async with self._lock:
            if token in self.tokens:
                del self.tokens[token]
                return True
            return False

    async def cleanup_expired(self) -> int:
        """Remove expired tokens from memory"""
        async with self._lock:
            expired_tokens = []
            current_time = datetime.now()
            
            for token, access_token in self.tokens.items():
                if access_token.expires_at < current_time:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                del self.tokens[token]
            
            return len(expired_tokens)


class RedisTokenStore(TokenStore):
    """Redis-based token store for production use"""

    def __init__(self, redis_client):
        """
        Initialize Redis token store
        
        Args:
            redis_client: Redis client instance (from redis-py or aioredis)
        """
        self.redis = redis_client
        self.prefix = "gauth:token:"

    async def store(self, token: str, access_token: AccessToken) -> None:
        """Store a token in Redis"""
        key = f"{self.prefix}{token}"
        
        # Calculate TTL based on expiration
        ttl_seconds = int((access_token.expires_at - datetime.now()).total_seconds())
        if ttl_seconds <= 0:
            return  # Don't store already expired tokens
        
        # Serialize token data
        token_data = {
            "token": access_token.token,
            "client_id": access_token.client_id,
            "scope": ",".join(access_token.scope),
            "expires_at": access_token.expires_at.isoformat(),
            "issued_at": access_token.issued_at.isoformat(),
            "restrictions": str(access_token.restrictions),  # Simple serialization
        }
        
        # Store with TTL
        if hasattr(self.redis, 'hset'):
            # Redis-py style
            await self.redis.hset(key, mapping=token_data)
            await self.redis.expire(key, ttl_seconds)
        else:
            # aioredis style
            await self.redis.hmset(key, token_data)
            await self.redis.expire(key, ttl_seconds)

    async def get(self, token: str) -> Optional[AccessToken]:
        """Retrieve a token from Redis"""
        key = f"{self.prefix}{token}"
        
        try:
            if hasattr(self.redis, 'hgetall'):
                # Redis-py style
                token_data = await self.redis.hgetall(key)
            else:
                # aioredis style
                token_data = await self.redis.hgetall(key)
            
            if not token_data:
                return None
            
            # Deserialize token data
            expires_at = datetime.fromisoformat(token_data["expires_at"])
            issued_at = datetime.fromisoformat(token_data["issued_at"])
            
            return AccessToken(
                token=token_data["token"],
                client_id=token_data["client_id"],
                scope=token_data["scope"].split(","),
                expires_at=expires_at,
                issued_at=issued_at,
                restrictions=[],  # Simplified for now
            )
            
        except Exception:
            return None

    async def delete(self, token: str) -> bool:
        """Delete a token from Redis"""
        key = f"{self.prefix}{token}"
        result = await self.redis.delete(key)
        return result > 0

    async def cleanup_expired(self) -> int:
        """Remove expired tokens from Redis (Redis handles this automatically with TTL)"""
        # Redis automatically removes expired keys, so we don't need to do anything
        # We could scan for any remaining expired keys, but it's usually not necessary
        return 0


# Factory function for creating token stores
def create_token_store(store_type: str = "memory", **kwargs) -> TokenStore:
    """
    Factory function to create token stores
    
    Args:
        store_type: Type of store ("memory" or "redis")
        **kwargs: Additional arguments for the store
        
    Returns:
        TokenStore instance
    """
    if store_type == "memory":
        return MemoryTokenStore()
    elif store_type == "redis":
        redis_client = kwargs.get("redis_client")
        if not redis_client:
            raise ValueError("redis_client is required for Redis token store")
        return RedisTokenStore(redis_client)
    else:
        raise ValueError(f"Unknown store type: {store_type}")


# Default store for convenience
def new_memory_store() -> TokenStore:
    """Create a new in-memory token store (for Go compatibility)"""
    return MemoryTokenStore()