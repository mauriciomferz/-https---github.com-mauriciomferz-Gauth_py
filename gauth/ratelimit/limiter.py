"""
Rate limiting implementation for GAuth.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, deque


class RateLimiter(ABC):
    """Abstract base class for rate limiting"""

    @abstractmethod
    async def allow(self, key: str) -> bool:
        """Check if a request is allowed for the given key"""
        pass

    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key"""
        pass

    async def close(self) -> None:
        """Close the rate limiter and release resources"""
        pass


class TokenBucketRateLimiter(RateLimiter):
    """Token bucket rate limiter implementation"""

    def __init__(
        self,
        max_requests: int = 100,
        time_window: timedelta = timedelta(minutes=1),
        burst_limit: int = 10,
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.burst_limit = burst_limit
        self.buckets: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        """Check if a request is allowed using token bucket algorithm"""
        async with self._lock:
            now = datetime.now()
            
            if key not in self.buckets:
                self.buckets[key] = {
                    "tokens": self.max_requests,
                    "last_update": now,
                }
            
            bucket = self.buckets[key]
            
            # Calculate tokens to add based on time elapsed
            time_elapsed = now - bucket["last_update"]
            tokens_to_add = (time_elapsed.total_seconds() / self.time_window.total_seconds()) * self.max_requests
            
            # Update bucket
            bucket["tokens"] = min(self.max_requests, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now
            
            # Check if request can be allowed
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True
            
            return False

    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key"""
        async with self._lock:
            if key in self.buckets:
                self.buckets[key] = {
                    "tokens": self.max_requests,
                    "last_update": datetime.now(),
                }


class SlidingWindowRateLimiter(RateLimiter):
    """Sliding window rate limiter implementation"""

    def __init__(
        self,
        max_requests: int = 100,
        time_window: timedelta = timedelta(minutes=1),
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        """Check if a request is allowed using sliding window algorithm"""
        async with self._lock:
            now = datetime.now()
            cutoff_time = now - self.time_window
            
            # Remove old requests outside the window
            while self.requests[key] and self.requests[key][0] < cutoff_time:
                self.requests[key].popleft()
            
            # Check if we can allow this request
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(now)
                return True
            
            return False

    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key"""
        async with self._lock:
            if key in self.requests:
                self.requests[key].clear()


class FixedWindowRateLimiter(RateLimiter):
    """Fixed window rate limiter implementation"""

    def __init__(
        self,
        max_requests: int = 100,
        time_window: timedelta = timedelta(minutes=1),
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.windows: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        """Check if a request is allowed using fixed window algorithm"""
        async with self._lock:
            now = datetime.now()
            window_start = self._get_window_start(now)
            
            if key not in self.windows:
                self.windows[key] = {}
            
            # Clean up old windows
            expired_windows = [w for w in self.windows[key] if w < window_start]
            for w in expired_windows:
                del self.windows[key][w]
            
            # Check current window
            if window_start not in self.windows[key]:
                self.windows[key][window_start] = 0
            
            if self.windows[key][window_start] < self.max_requests:
                self.windows[key][window_start] += 1
                return True
            
            return False

    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key"""
        async with self._lock:
            if key in self.windows:
                self.windows[key].clear()

    def _get_window_start(self, timestamp: datetime) -> datetime:
        """Get the start of the current window"""
        window_seconds = int(self.time_window.total_seconds())
        epoch_seconds = int(timestamp.timestamp())
        window_start_seconds = (epoch_seconds // window_seconds) * window_seconds
        return datetime.fromtimestamp(window_start_seconds)


class RedisRateLimiter(RateLimiter):
    """Redis-based rate limiter for distributed systems"""

    def __init__(
        self,
        redis_client,
        max_requests: int = 100,
        time_window: timedelta = timedelta(minutes=1),
        algorithm: str = "sliding_window",
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.time_window = time_window
        self.algorithm = algorithm
        self.prefix = "gauth:ratelimit:"

    async def allow(self, key: str) -> bool:
        """Check if a request is allowed using Redis"""
        redis_key = f"{self.prefix}{key}"
        
        if self.algorithm == "fixed_window":
            return await self._fixed_window_check(redis_key)
        else:  # sliding_window
            return await self._sliding_window_check(redis_key)

    async def _fixed_window_check(self, redis_key: str) -> bool:
        """Fixed window rate limiting with Redis"""
        now = datetime.now()
        window_start = self._get_window_start(now)
        window_key = f"{redis_key}:{int(window_start.timestamp())}"
        
        try:
            # Use pipeline for atomic operations
            pipe = self.redis.pipeline()
            pipe.incr(window_key)
            pipe.expire(window_key, int(self.time_window.total_seconds()))
            results = await pipe.execute()
            
            count = results[0]
            return count <= self.max_requests
            
        except Exception:
            # Allow request if Redis is unavailable
            return True

    async def _sliding_window_check(self, redis_key: str) -> bool:
        """Sliding window rate limiting with Redis"""
        now = datetime.now()
        cutoff_time = now - self.time_window
        
        try:
            # Use sorted set to maintain requests in time order
            pipe = self.redis.pipeline()
            
            # Remove old requests
            pipe.zremrangebyscore(redis_key, 0, cutoff_time.timestamp())
            
            # Count current requests
            pipe.zcard(redis_key)
            
            # Add current request if under limit
            pipe.zadd(redis_key, {str(now.timestamp()): now.timestamp()})
            
            # Set expiration
            pipe.expire(redis_key, int(self.time_window.total_seconds()))
            
            results = await pipe.execute()
            count = results[1]  # Count before adding new request
            
            if count < self.max_requests:
                return True
            else:
                # Remove the request we just added if over limit
                await self.redis.zrem(redis_key, str(now.timestamp()))
                return False
                
        except Exception:
            # Allow request if Redis is unavailable
            return True

    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key"""
        redis_key = f"{self.prefix}{key}"
        try:
            await self.redis.delete(redis_key)
        except Exception:
            pass  # Ignore errors when resetting

    def _get_window_start(self, timestamp: datetime) -> datetime:
        """Get the start of the current window"""
        window_seconds = int(self.time_window.total_seconds())
        epoch_seconds = int(timestamp.timestamp())
        window_start_seconds = (epoch_seconds // window_seconds) * window_seconds
        return datetime.fromtimestamp(window_start_seconds)


# Factory function for creating rate limiters
def create_rate_limiter(
    limiter_type: str = "token_bucket",
    max_requests: int = 100,
    time_window: timedelta = timedelta(minutes=1),
    **kwargs
) -> RateLimiter:
    """
    Factory function to create rate limiters
    
    Args:
        limiter_type: Type of limiter ("token_bucket", "sliding_window", "fixed_window", "redis")
        max_requests: Maximum requests allowed
        time_window: Time window for rate limiting
        **kwargs: Additional arguments for the limiter
        
    Returns:
        RateLimiter instance
    """
    if limiter_type == "token_bucket":
        burst_limit = kwargs.get("burst_limit", 10)
        return TokenBucketRateLimiter(max_requests, time_window, burst_limit)
    elif limiter_type == "sliding_window":
        return SlidingWindowRateLimiter(max_requests, time_window)
    elif limiter_type == "fixed_window":
        return FixedWindowRateLimiter(max_requests, time_window)
    elif limiter_type == "redis":
        redis_client = kwargs.get("redis_client")
        if not redis_client:
            raise ValueError("redis_client is required for Redis rate limiter")
        algorithm = kwargs.get("algorithm", "sliding_window")
        return RedisRateLimiter(redis_client, max_requests, time_window, algorithm)
    else:
        raise ValueError(f"Unknown limiter type: {limiter_type}")


# Default limiter for convenience
def new_limiter(
    max_requests: int = 100,
    time_window: timedelta = timedelta(minutes=1)
) -> RateLimiter:
    """Create a new token bucket rate limiter (for Go compatibility)"""
    return TokenBucketRateLimiter(max_requests, time_window)