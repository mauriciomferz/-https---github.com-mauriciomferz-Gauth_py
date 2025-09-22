"""
Rate limiting implementation for GAuth.

This module provides comprehensive rate limiting functionality with support for
multiple algorithms, distributed backends, and dynamic limit adjustments.
"""

import asyncio
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional, List, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import deque
import json

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from ..common.utils import get_current_time, generate_id
from ..common.messages import ErrorMessages


logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    """Base exception for rate limiting errors."""
    pass


class RateLimitExceeded(RateLimitError):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", 
                 retry_after: Optional[float] = None,
                 remaining: int = 0):
        super().__init__(message)
        self.retry_after = retry_after
        self.remaining = remaining


class InvalidConfigError(RateLimitError):
    """Exception raised when rate limiter configuration is invalid."""
    pass


@dataclass
class RateLimitConfig:
    """Configuration for rate limiters."""
    
    rate: int  # Number of requests allowed per window
    window: float  # Time window in seconds
    burst_size: Optional[int] = None  # Maximum burst size for token bucket
    backend: str = "memory"  # Backend type: memory, redis
    redis_url: Optional[str] = None  # Redis connection URL
    redis_key_prefix: str = "gauth:rate:"  # Redis key prefix
    cleanup_interval: float = 300.0  # Cleanup interval in seconds
    
    def __post_init__(self):
        if self.rate <= 0:
            raise InvalidConfigError("Rate must be positive")
        if self.window <= 0:
            raise InvalidConfigError("Window must be positive")
        if self.burst_size is None:
            self.burst_size = max(self.rate, 10)
        if self.burst_size < self.rate:
            self.burst_size = self.rate


@dataclass
class RateLimitQuota:
    """Information about rate limit quota."""
    
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "allowed": self.allowed,
            "remaining": self.remaining,
            "reset_time": self.reset_time.isoformat(),
            "retry_after": self.retry_after
        }


class RateLimiter(ABC):
    """Abstract base class for rate limiters."""
    
    @abstractmethod
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if a request is allowed for the given identifier."""
        pass
    
    @abstractmethod
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for the identifier."""
        pass
    
    @abstractmethod
    async def reset(self, identifier: str) -> None:
        """Reset rate limit for the identifier."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up expired entries."""
        pass


class TokenBucketLimiter(RateLimiter):
    """Token bucket rate limiting algorithm."""
    
    def __init__(self, config: RateLimitConfig):
        """
        Initialize token bucket limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self.rate_per_second = config.rate / config.window
        self.burst_size = config.burst_size
        self._buckets: Dict[str, Dict[str, float]] = {}
        self._lock = asyncio.Lock()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using token bucket algorithm."""
        async with self._lock:
            now = time.time()
            
            # Get or create bucket
            if identifier not in self._buckets:
                self._buckets[identifier] = {
                    "tokens": float(self.burst_size),
                    "last_update": now
                }
            
            bucket = self._buckets[identifier]
            
            # Calculate token replenishment
            time_passed = now - bucket["last_update"]
            tokens_to_add = time_passed * self.rate_per_second
            bucket["tokens"] = min(self.burst_size, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now
            
            # Check if request can be allowed
            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                remaining = int(bucket["tokens"])
                reset_time = get_current_time() + timedelta(seconds=self.config.window)
                
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Calculate retry after
                retry_after = (1.0 - bucket["tokens"]) / self.rate_per_second
                reset_time = get_current_time() + timedelta(seconds=retry_after)
                
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining tokens for identifier."""
        async with self._lock:
            if identifier not in self._buckets:
                return self.burst_size
            
            bucket = self._buckets[identifier]
            now = time.time()
            
            # Update tokens
            time_passed = now - bucket["last_update"]
            tokens_to_add = time_passed * self.rate_per_second
            bucket["tokens"] = min(self.burst_size, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now
            
            return int(bucket["tokens"])
    
    async def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier."""
        async with self._lock:
            if identifier in self._buckets:
                self._buckets[identifier] = {
                    "tokens": float(self.burst_size),
                    "last_update": time.time()
                }
    
    async def cleanup(self) -> None:
        """Clean up expired buckets."""
        async with self._lock:
            now = time.time()
            expired_keys = []
            
            for identifier, bucket in self._buckets.items():
                # Remove buckets that haven't been accessed for a while
                if now - bucket["last_update"] > self.config.cleanup_interval:
                    expired_keys.append(identifier)
            
            for key in expired_keys:
                del self._buckets[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired rate limit buckets")
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        try:
            while True:
                await asyncio.sleep(self.config.cleanup_interval)
                await self.cleanup()
        except asyncio.CancelledError:
            logger.debug("Token bucket cleanup loop cancelled")
        except Exception as e:
            logger.error(f"Error in token bucket cleanup loop: {e}")
    
    async def close(self) -> None:
        """Close the limiter and cleanup resources."""
        if hasattr(self, '_cleanup_task'):
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


class SlidingWindowLimiter(RateLimiter):
    """Sliding window rate limiting algorithm."""
    
    def __init__(self, config: RateLimitConfig):
        """
        Initialize sliding window limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self._windows: Dict[str, deque] = {}
        self._lock = asyncio.Lock()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using sliding window algorithm."""
        async with self._lock:
            now = time.time()
            window_start = now - self.config.window
            
            # Get or create window
            if identifier not in self._windows:
                self._windows[identifier] = deque()
            
            window = self._windows[identifier]
            
            # Remove old timestamps
            while window and window[0] <= window_start:
                window.popleft()
            
            # Check if request can be allowed
            if len(window) < self.config.rate:
                window.append(now)
                remaining = self.config.rate - len(window)
                reset_time = get_current_time() + timedelta(seconds=self.config.window)
                
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Calculate retry after (time until oldest request expires)
                oldest_request = window[0]
                retry_after = oldest_request + self.config.window - now
                reset_time = get_current_time() + timedelta(seconds=retry_after)
                
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        async with self._lock:
            if identifier not in self._windows:
                return self.config.rate
            
            now = time.time()
            window_start = now - self.config.window
            window = self._windows[identifier]
            
            # Remove old timestamps
            while window and window[0] <= window_start:
                window.popleft()
            
            return self.config.rate - len(window)
    
    async def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier."""
        async with self._lock:
            if identifier in self._windows:
                self._windows[identifier].clear()
    
    async def cleanup(self) -> None:
        """Clean up expired windows."""
        async with self._lock:
            now = time.time()
            window_start = now - self.config.window
            expired_keys = []
            
            for identifier, window in self._windows.items():
                # Remove old timestamps
                while window and window[0] <= window_start:
                    window.popleft()
                
                # Remove empty windows that haven't been used for a while
                if not window:
                    expired_keys.append(identifier)
            
            for key in expired_keys:
                del self._windows[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired rate limit windows")
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        try:
            while True:
                await asyncio.sleep(self.config.cleanup_interval)
                await self.cleanup()
        except asyncio.CancelledError:
            logger.debug("Sliding window cleanup loop cancelled")
        except Exception as e:
            logger.error(f"Error in sliding window cleanup loop: {e}")
    
    async def close(self) -> None:
        """Close the limiter and cleanup resources."""
        if hasattr(self, '_cleanup_task'):
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


class FixedWindowLimiter(RateLimiter):
    """Fixed window rate limiting algorithm."""
    
    def __init__(self, config: RateLimitConfig):
        """
        Initialize fixed window limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self._windows: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    def _get_window_key(self, timestamp: float) -> int:
        """Get window key for given timestamp."""
        return int(timestamp // self.config.window)
    
    async def allow(self, identifier: str) -> RateLimitQuota:
        """Check if request is allowed using fixed window algorithm."""
        async with self._lock:
            now = time.time()
            window_key = self._get_window_key(now)
            
            # Get or create window data
            if identifier not in self._windows:
                self._windows[identifier] = {}
            
            user_windows = self._windows[identifier]
            
            # Clean old windows
            current_window_start = window_key * self.config.window
            old_keys = [k for k in user_windows.keys() 
                       if k < window_key and (now - k * self.config.window) > self.config.window * 2]
            for old_key in old_keys:
                del user_windows[old_key]
            
            # Get current window count
            current_count = user_windows.get(window_key, 0)
            
            # Check if request can be allowed
            if current_count < self.config.rate:
                user_windows[window_key] = current_count + 1
                remaining = self.config.rate - (current_count + 1)
                
                # Calculate reset time (end of current window)
                window_end = (window_key + 1) * self.config.window
                reset_time = datetime.fromtimestamp(window_end)
                
                return RateLimitQuota(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Calculate retry after (time until next window)
                window_end = (window_key + 1) * self.config.window
                retry_after = window_end - now
                reset_time = datetime.fromtimestamp(window_end)
                
                return RateLimitQuota(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        async with self._lock:
            if identifier not in self._windows:
                return self.config.rate
            
            now = time.time()
            window_key = self._get_window_key(now)
            user_windows = self._windows[identifier]
            current_count = user_windows.get(window_key, 0)
            
            return self.config.rate - current_count
    
    async def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier."""
        async with self._lock:
            if identifier in self._windows:
                self._windows[identifier].clear()
    
    async def cleanup(self) -> None:
        """Clean up expired windows."""
        async with self._lock:
            now = time.time()
            current_window = self._get_window_key(now)
            expired_identifiers = []
            
            for identifier, user_windows in self._windows.items():
                # Remove old windows
                old_keys = [k for k in user_windows.keys() 
                           if k < current_window - 2]  # Keep some history
                for old_key in old_keys:
                    del user_windows[old_key]
                
                # Remove identifiers with no recent activity
                if not user_windows:
                    expired_identifiers.append(identifier)
            
            for identifier in expired_identifiers:
                del self._windows[identifier]
            
            if expired_identifiers:
                logger.debug(f"Cleaned up {len(expired_identifiers)} expired rate limit identifiers")
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        try:
            while True:
                await asyncio.sleep(self.config.cleanup_interval)
                await self.cleanup()
        except asyncio.CancelledError:
            logger.debug("Fixed window cleanup loop cancelled")
        except Exception as e:
            logger.error(f"Error in fixed window cleanup loop: {e}")
    
    async def close(self) -> None:
        """Close the limiter and cleanup resources."""
        if hasattr(self, '_cleanup_task'):
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


def create_rate_limiter(algorithm: str = "token_bucket", 
                       config: RateLimitConfig = None) -> RateLimiter:
    """
    Create a rate limiter with the specified algorithm.
    
    Args:
        algorithm: Rate limiting algorithm (token_bucket, sliding_window, fixed_window)
        config: Rate limiting configuration
    
    Returns:
        RateLimiter instance
    
    Raises:
        ValueError: If algorithm is not supported
    """
    if config is None:
        config = RateLimitConfig(rate=100, window=60.0)
    
    algorithms = {
        "token_bucket": TokenBucketLimiter,
        "sliding_window": SlidingWindowLimiter,
        "fixed_window": FixedWindowLimiter
    }
    
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}. "
                        f"Supported algorithms: {list(algorithms.keys())}")
    
    return algorithms[algorithm](config)


# Convenience functions
def create_token_bucket_limiter(rate: int, 
                              window: float = 60.0, 
                              burst_size: Optional[int] = None) -> TokenBucketLimiter:
    """Create a token bucket rate limiter."""
    config = RateLimitConfig(
        rate=rate, 
        window=window, 
        burst_size=burst_size or max(rate, 10)
    )
    return TokenBucketLimiter(config)


def create_sliding_window_limiter(rate: int, 
                                window: float = 60.0) -> SlidingWindowLimiter:
    """Create a sliding window rate limiter."""
    config = RateLimitConfig(rate=rate, window=window)
    return SlidingWindowLimiter(config)


def create_fixed_window_limiter(rate: int, 
                              window: float = 60.0) -> FixedWindowLimiter:
    """Create a fixed window rate limiter."""
    config = RateLimitConfig(rate=rate, window=window)
    return FixedWindowLimiter(config)