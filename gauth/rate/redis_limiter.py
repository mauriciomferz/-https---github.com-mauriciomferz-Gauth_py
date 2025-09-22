"""
Redis-based distributed rate limiting for GAuth.

This module provides Redis-backed rate limiters that can be used
across multiple application instances for distributed rate limiting.
"""

import asyncio
import time
import json
import logging
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .limiter import RateLimiter, RateLimitConfig, RateLimitQuota, RateLimitExceeded
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class RedisRateLimiter(RateLimiter):
    """Redis-based distributed rate limiter."""
    
    def __init__(self, config: RateLimitConfig, redis_client: Any = None):
        """
        Initialize Redis rate limiter.
        
        Args:
            config: Rate limiting configuration
            redis_client: Redis client instance
        """
        if not REDIS_AVAILABLE:
            raise ImportError("redis package is required for RedisRateLimiter")
        
        self.config = config
        self.redis_client = redis_client
        
        if self.redis_client is None:
            if config.redis_url:
                self.redis_client = redis.from_url(config.redis_url)
            else:
                self.redis_client = redis.Redis()
        
        self.key_prefix = config.redis_key_prefix
    
    def _get_key(self, identifier: str, suffix: str = "") -> str:
        """Generate Redis key for identifier."""
        key = f"{self.key_prefix}{identifier}"
        if suffix:
            key += f":{suffix}"
        return key
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement allow method")
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement get_remaining method")
    
    async def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier."""
        pattern = self._get_key(identifier, "*")
        keys = await self.redis_client.keys(pattern)
        if keys:
            await self.redis_client.delete(*keys)
    
    async def cleanup(self) -> None:
        """Cleanup expired keys (Redis handles TTL automatically)."""
        # Redis handles expiration automatically, but we can do manual cleanup if needed
        pass
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()


class RedisTokenBucketLimiter(RedisRateLimiter):
    """Redis-based token bucket rate limiter."""
    
    def __init__(self, config: RateLimitConfig, redis_client: Any = None):
        """Initialize Redis token bucket limiter."""
        super().__init__(config, redis_client)
        self.rate_per_second = config.rate / config.window
        self.burst_size = config.burst_size
        
        # Lua script for atomic token bucket operations
        self.lua_script = """
        local key = KEYS[1]
        local rate_per_second = tonumber(ARGV[1])
        local burst_size = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local ttl = tonumber(ARGV[4])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_update')
        local tokens = tonumber(bucket[1])
        local last_update = tonumber(bucket[2])
        
        if tokens == nil then
            tokens = burst_size
            last_update = now
        end
        
        -- Calculate token replenishment
        local time_passed = now - last_update
        local tokens_to_add = time_passed * rate_per_second
        tokens = math.min(burst_size, tokens + tokens_to_add)
        
        -- Check if request can be allowed
        local allowed = 0
        local remaining = math.floor(tokens)
        local retry_after = 0
        
        if tokens >= 1 then
            tokens = tokens - 1
            allowed = 1
            remaining = math.floor(tokens)
        else
            retry_after = (1 - tokens) / rate_per_second
        end
        
        -- Update bucket state
        redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        redis.call('EXPIRE', key, ttl)
        
        return {allowed, remaining, retry_after}
        """
        
        self.script_sha = None
    
    async def _ensure_script_loaded(self) -> str:
        """Ensure Lua script is loaded into Redis."""
        if self.script_sha is None:
            self.script_sha = await self.redis_client.script_load(self.lua_script)
        return self.script_sha
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using Redis token bucket."""
        key = self._get_key(identifier, "bucket")
        now = time.time()
        ttl = int(self.config.window * 2)  # TTL longer than window
        
        try:
            script_sha = await self._ensure_script_loaded()
            result = await self.redis_client.evalsha(
                script_sha,
                1,  # number of keys
                key,
                self.rate_per_second,
                self.burst_size,
                now,
                ttl
            )
            
            allowed, remaining, retry_after = result
            
            if allowed:
                reset_time = get_current_time() + timedelta(seconds=self.config.window)
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                reset_time = get_current_time() + timedelta(seconds=retry_after)
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
                
        except Exception as e:
            logger.error(f"Redis token bucket error: {e}")
            # Fallback to allow on Redis error
            reset_time = get_current_time() + timedelta(seconds=self.config.window)
            return RateLimitQuota(
                allowed=True,
                remaining=self.burst_size,
                reset_time=reset_time
            )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining tokens for identifier."""
        key = self._get_key(identifier, "bucket")
        
        try:
            bucket = await self.redis_client.hmget(key, "tokens", "last_update")
            tokens = bucket[0]
            last_update = bucket[1]
            
            if tokens is None:
                return self.burst_size
            
            # Update tokens based on time passed
            now = time.time()
            time_passed = now - float(last_update)
            tokens_to_add = time_passed * self.rate_per_second
            current_tokens = min(self.burst_size, float(tokens) + tokens_to_add)
            
            return int(current_tokens)
            
        except Exception as e:
            logger.error(f"Redis get remaining error: {e}")
            return self.burst_size


class RedisSlidingWindowLimiter(RedisRateLimiter):
    """Redis-based sliding window rate limiter."""
    
    def __init__(self, config: RateLimitConfig, redis_client: Any = None):
        """Initialize Redis sliding window limiter."""
        super().__init__(config, redis_client)
        
        # Lua script for atomic sliding window operations
        self.lua_script = """
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local ttl = tonumber(ARGV[4])
        
        local window_start = now - window
        
        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Count current entries
        local current = redis.call('ZCARD', key)
        
        local allowed = 0
        local remaining = limit - current
        local retry_after = 0
        
        if current < limit then
            -- Add new entry
            redis.call('ZADD', key, now, now)
            redis.call('EXPIRE', key, ttl)
            allowed = 1
            remaining = remaining - 1
        else
            -- Calculate retry after (time until oldest entry expires)
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            if #oldest > 0 then
                retry_after = tonumber(oldest[2]) + window - now
            end
        end
        
        return {allowed, remaining, retry_after}
        """
        
        self.script_sha = None
    
    async def _ensure_script_loaded(self) -> str:
        """Ensure Lua script is loaded into Redis."""
        if self.script_sha is None:
            self.script_sha = await self.redis_client.script_load(self.lua_script)
        return self.script_sha
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using Redis sliding window."""
        key = self._get_key(identifier, "window")
        now = time.time()
        ttl = int(self.config.window * 2)
        
        try:
            script_sha = await self._ensure_script_loaded()
            result = await self.redis_client.evalsha(
                script_sha,
                1,  # number of keys
                key,
                self.config.window,
                self.config.rate,
                now,
                ttl
            )
            
            allowed, remaining, retry_after = result
            
            if allowed:
                reset_time = get_current_time() + timedelta(seconds=self.config.window)
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                reset_time = get_current_time() + timedelta(seconds=retry_after)
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
                
        except Exception as e:
            logger.error(f"Redis sliding window error: {e}")
            # Fallback to allow on Redis error
            reset_time = get_current_time() + timedelta(seconds=self.config.window)
            return RateLimitQuota(
                allowed=True,
                remaining=self.config.rate,
                reset_time=reset_time
            )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        key = self._get_key(identifier, "window")
        
        try:
            now = time.time()
            window_start = now - self.config.window
            
            # Remove old entries and count current
            await self.redis_client.zremrangebyscore(key, 0, window_start)
            current = await self.redis_client.zcard(key)
            
            return self.config.rate - current
            
        except Exception as e:
            logger.error(f"Redis get remaining error: {e}")
            return self.config.rate


class RedisFixedWindowLimiter(RedisRateLimiter):
    """Redis-based fixed window rate limiter."""
    
    def __init__(self, config: RateLimitConfig, redis_client: Any = None):
        """Initialize Redis fixed window limiter."""
        super().__init__(config, redis_client)
    
    def _get_window_key(self, identifier: str, timestamp: float) -> str:
        """Get window key for given timestamp."""
        window_number = int(timestamp // self.config.window)
        return self._get_key(identifier, f"window:{window_number}")
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using Redis fixed window."""
        now = time.time()
        window_key = self._get_window_key(identifier, now)
        window_number = int(now // self.config.window)
        
        try:
            # Increment counter for current window
            current = await self.redis_client.incr(window_key)
            
            # Set TTL for the key (window duration + buffer)
            if current == 1:
                await self.redis_client.expire(window_key, int(self.config.window * 2))
            
            if current <= self.config.rate:
                remaining = self.config.rate - current
                window_end = (window_number + 1) * self.config.window
                reset_time = datetime.fromtimestamp(window_end)
                
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Calculate retry after (time until next window)
                window_end = (window_number + 1) * self.config.window
                retry_after = window_end - now
                reset_time = datetime.fromtimestamp(window_end)
                
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
                
        except Exception as e:
            logger.error(f"Redis fixed window error: {e}")
            # Fallback to allow on Redis error
            window_end = (window_number + 1) * self.config.window
            reset_time = datetime.fromtimestamp(window_end)
            return RateLimitQuota(
                allowed=True,
                remaining=self.config.rate,
                reset_time=reset_time
            )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        now = time.time()
        window_key = self._get_window_key(identifier, now)
        
        try:
            current = await self.redis_client.get(window_key)
            if current is None:
                return self.config.rate
            
            return max(0, self.config.rate - int(current))
            
        except Exception as e:
            logger.error(f"Redis get remaining error: {e}")
            return self.config.rate


def create_redis_rate_limiter(algorithm: str = "token_bucket",
                            config: RateLimitConfig = None,
                            redis_client: Any = None) -> RedisRateLimiter:
    """
    Create a Redis-based rate limiter.
    
    Args:
        algorithm: Rate limiting algorithm (token_bucket, sliding_window, fixed_window)
        config: Rate limiting configuration
        redis_client: Redis client instance
    
    Returns:
        RedisRateLimiter instance
    
    Raises:
        ValueError: If algorithm is not supported
        ImportError: If redis package is not available
    """
    if not REDIS_AVAILABLE:
        raise ImportError("redis package is required for Redis rate limiters")
    
    if config is None:
        config = RateLimitConfig(rate=100, window=60.0, backend="redis")
    
    algorithms = {
        "token_bucket": RedisTokenBucketLimiter,
        "sliding_window": RedisSlidingWindowLimiter,
        "fixed_window": RedisFixedWindowLimiter
    }
    
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}. "
                        f"Supported algorithms: {list(algorithms.keys())}")
    
    return algorithms[algorithm](config, redis_client)


# Convenience functions
def create_redis_token_bucket(rate: int,
                            window: float = 60.0,
                            burst_size: Optional[int] = None,
                            redis_url: Optional[str] = None) -> RedisTokenBucketLimiter:
    """Create a Redis token bucket rate limiter."""
    config = RateLimitConfig(
        rate=rate,
        window=window,
        burst_size=burst_size or max(rate, 10),
        backend="redis",
        redis_url=redis_url
    )
    return RedisTokenBucketLimiter(config)


def create_redis_sliding_window(rate: int,
                               window: float = 60.0,
                               redis_url: Optional[str] = None) -> RedisSlidingWindowLimiter:
    """Create a Redis sliding window rate limiter."""
    config = RateLimitConfig(
        rate=rate,
        window=window,
        backend="redis",
        redis_url=redis_url
    )
    return RedisSlidingWindowLimiter(config)


def create_redis_fixed_window(rate: int,
                             window: float = 60.0,
                             redis_url: Optional[str] = None) -> RedisFixedWindowLimiter:
    """Create a Redis fixed window rate limiter."""
    config = RateLimitConfig(
        rate=rate,
        window=window,
        backend="redis",
        redis_url=redis_url
    )
    return RedisFixedWindowLimiter(config)