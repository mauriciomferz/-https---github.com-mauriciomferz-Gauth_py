"""
Sliding window rate limiting implementation for GAuth.

This module provides sliding window rate limiting for more accurate
rate control over precise time periods.
"""

import asyncio
import time
import logging
from collections import deque
from dataclasses import dataclass
from typing import Dict, Optional, List
from datetime import datetime, timedelta

from .limiter import RateLimiter


logger = logging.getLogger(__name__)


@dataclass
class SlidingWindowConfig:
    """Configuration for sliding window rate limiting."""
    limit: int = 100
    window_seconds: float = 60.0
    cleanup_interval: float = 300.0  # 5 minutes


class SlidingWindowRateLimiter(RateLimiter):
    """
    Sliding window rate limiter implementation.
    
    This limiter maintains a sliding time window and tracks all requests
    within that window for precise rate limiting.
    """
    
    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        """Initialize the sliding window rate limiter."""
        self.config = config or SlidingWindowConfig()
        self.windows: Dict[str, deque] = {}
        self.last_cleanup = time.time()
        self._lock = asyncio.Lock()
    
    async def allow(self, key: str) -> bool:
        """
        Check if a request is allowed for the given key.
        
        Args:
            key: Identifier for the client/resource
            
        Returns:
            True if request is allowed, False otherwise
        """
        async with self._lock:
            current_time = time.time()
            
            # Get or create window for key
            if key not in self.windows:
                self.windows[key] = deque()
            
            window = self.windows[key]
            
            # Remove old requests outside the window
            window_start = current_time - self.config.window_seconds
            while window and window[0] < window_start:
                window.popleft()
            
            # Check if we can allow the request
            if len(window) >= self.config.limit:
                logger.debug(f"Rate limit exceeded for key {key}: {len(window)}/{self.config.limit}")
                return False
            
            # Add the current request
            window.append(current_time)
            
            # Cleanup if needed
            await self._cleanup_if_needed(current_time)
            
            return True
    
    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key."""
        async with self._lock:
            if key in self.windows:
                self.windows[key].clear()
    
    async def _cleanup_if_needed(self, current_time: float) -> None:
        """Clean up old windows if needed."""
        if current_time - self.last_cleanup < self.config.cleanup_interval:
            return
        
        # Remove empty or very old windows
        keys_to_remove = []
        window_start = current_time - self.config.window_seconds * 2
        
        for key, window in self.windows.items():
            # Remove old requests
            while window and window[0] < window_start:
                window.popleft()
            
            # Mark empty windows for removal
            if not window:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.windows[key]
        
        self.last_cleanup = current_time
        
        if keys_to_remove:
            logger.debug(f"Cleaned up {len(keys_to_remove)} empty sliding windows")
    
    def get_stats(self) -> Dict[str, any]:
        """Get current statistics."""
        return {
            "active_windows": len(self.windows),
            "total_requests": sum(len(window) for window in self.windows.values()),
            "window_seconds": self.config.window_seconds,
            "limit": self.config.limit,
        }
    
    def get_window_usage(self, key: str) -> Dict[str, any]:
        """Get usage information for a specific key."""
        if key not in self.windows:
            return {
                "current_count": 0,
                "limit": self.config.limit,
                "remaining": self.config.limit,
                "window_seconds": self.config.window_seconds,
            }
        
        window = self.windows[key]
        current_time = time.time()
        window_start = current_time - self.config.window_seconds
        
        # Count valid requests in window
        valid_requests = sum(1 for req_time in window if req_time >= window_start)
        
        return {
            "current_count": valid_requests,
            "limit": self.config.limit,
            "remaining": max(0, self.config.limit - valid_requests),
            "window_seconds": self.config.window_seconds,
            "oldest_request": min(window) if window else None,
            "newest_request": max(window) if window else None,
        }


class FixedWindowRateLimiter(RateLimiter):
    """
    Fixed window rate limiter implementation.
    
    This limiter uses fixed time windows that reset at regular intervals.
    Simpler than sliding window but less accurate.
    """
    
    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        """Initialize the fixed window rate limiter."""
        self.config = config or SlidingWindowConfig()
        self.windows: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
    
    async def allow(self, key: str) -> bool:
        """
        Check if a request is allowed for the given key.
        
        Args:
            key: Identifier for the client/resource
            
        Returns:
            True if request is allowed, False otherwise
        """
        async with self._lock:
            current_time = time.time()
            window_number = int(current_time // self.config.window_seconds)
            
            # Get or create window for key
            if key not in self.windows:
                self.windows[key] = {}
            
            key_windows = self.windows[key]
            
            # Clean up old windows
            old_windows = [w for w in key_windows.keys() if w < window_number - 1]
            for old_window in old_windows:
                del key_windows[old_window]
            
            # Get current window count
            current_count = key_windows.get(window_number, 0)
            
            # Check if we can allow the request
            if current_count >= self.config.limit:
                logger.debug(f"Rate limit exceeded for key {key}: {current_count}/{self.config.limit}")
                return False
            
            # Increment count
            key_windows[window_number] = current_count + 1
            
            return True
    
    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key."""
        async with self._lock:
            if key in self.windows:
                self.windows[key].clear()
    
    def get_stats(self) -> Dict[str, any]:
        """Get current statistics."""
        total_windows = sum(len(key_windows) for key_windows in self.windows.values())
        total_requests = sum(
            sum(key_windows.values()) 
            for key_windows in self.windows.values()
        )
        
        return {
            "active_keys": len(self.windows),
            "total_windows": total_windows,
            "total_requests": total_requests,
            "window_seconds": self.config.window_seconds,
            "limit": self.config.limit,
        }
    
    def get_window_usage(self, key: str) -> Dict[str, any]:
        """Get usage information for a specific key."""
        current_time = time.time()
        window_number = int(current_time // self.config.window_seconds)
        
        if key not in self.windows:
            return {
                "current_count": 0,
                "limit": self.config.limit,
                "remaining": self.config.limit,
                "window_number": window_number,
                "window_seconds": self.config.window_seconds,
            }
        
        current_count = self.windows[key].get(window_number, 0)
        
        return {
            "current_count": current_count,
            "limit": self.config.limit,
            "remaining": max(0, self.config.limit - current_count),
            "window_number": window_number,
            "window_seconds": self.config.window_seconds,
        }


def create_sliding_window_limiter(config: Optional[SlidingWindowConfig] = None) -> SlidingWindowRateLimiter:
    """Factory function to create a sliding window rate limiter."""
    return SlidingWindowRateLimiter(config)


def create_fixed_window_limiter(config: Optional[SlidingWindowConfig] = None) -> FixedWindowRateLimiter:
    """Factory function to create a fixed window rate limiter."""
    return FixedWindowRateLimiter(config)