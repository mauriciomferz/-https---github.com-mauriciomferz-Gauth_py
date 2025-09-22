"""
Adaptive rate limiting implementation for GAuth.

This module provides adaptive rate limiting that adjusts limits based on usage patterns.
"""

import asyncio
import time
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from collections import deque

from .limiter import RateLimiter


logger = logging.getLogger(__name__)


@dataclass
class AdaptiveConfig:
    """Configuration for adaptive rate limiting."""
    initial_limit: int = 100
    max_limit: int = 1000
    min_limit: int = 10
    window_seconds: float = 60.0
    scale_up_factor: float = 1.1
    scale_down_factor: float = 0.9
    history_size: int = 10
    adaptation_threshold: float = 0.8


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts limits based on usage patterns.
    
    The limiter monitors usage patterns and automatically adjusts the rate limit:
    - Scales up when usage is consistently below threshold
    - Scales down when usage consistently exceeds threshold
    """
    
    def __init__(self, config: Optional[AdaptiveConfig] = None):
        """Initialize the adaptive rate limiter."""
        self.config = config or AdaptiveConfig()
        self.current_limit = self.config.initial_limit
        self.last_reset = time.time()
        self.usage_history: deque = deque(maxlen=self.config.history_size)
        self.request_counts: Dict[str, int] = {}
        self.last_adaptation = time.time()
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
            
            # Reset window if needed
            if current_time - self.last_reset >= self.config.window_seconds:
                await self._reset_window(current_time)
            
            # Get current count for key
            current_count = self.request_counts.get(key, 0)
            
            # Check if within current limit
            if current_count >= self.current_limit:
                logger.debug(f"Rate limit exceeded for key {key}: {current_count}/{self.current_limit}")
                return False
            
            # Increment count
            self.request_counts[key] = current_count + 1
            
            return True
    
    async def reset(self, key: str) -> None:
        """Reset rate limit for a specific key."""
        async with self._lock:
            if key in self.request_counts:
                del self.request_counts[key]
    
    async def _reset_window(self, current_time: float) -> None:
        """Reset the time window and adapt limits based on usage."""
        # Calculate usage rate for this window
        total_requests = sum(self.request_counts.values())
        usage_rate = total_requests / self.current_limit if self.current_limit > 0 else 0
        
        # Add to usage history
        self.usage_history.append(usage_rate)
        
        # Adapt limits if we have enough history
        if len(self.usage_history) >= 3:
            await self._adapt_limits()
        
        # Reset counters
        self.request_counts.clear()
        self.last_reset = current_time
        
        logger.debug(f"Window reset. Usage rate: {usage_rate:.2f}, Current limit: {self.current_limit}")
    
    async def _adapt_limits(self) -> None:
        """Adapt the rate limit based on usage patterns."""
        current_time = time.time()
        
        # Don't adapt too frequently
        if current_time - self.last_adaptation < self.config.window_seconds:
            return
        
        # Calculate average usage rate
        avg_usage = sum(self.usage_history) / len(self.usage_history)
        
        old_limit = self.current_limit
        
        # Scale up if usage is consistently low
        if avg_usage < self.config.adaptation_threshold:
            new_limit = int(self.current_limit * self.config.scale_up_factor)
            self.current_limit = min(new_limit, self.config.max_limit)
        
        # Scale down if usage is consistently high
        elif avg_usage > self.config.adaptation_threshold:
            new_limit = int(self.current_limit * self.config.scale_down_factor)
            self.current_limit = max(new_limit, self.config.min_limit)
        
        if self.current_limit != old_limit:
            logger.info(f"Adapted rate limit: {old_limit} -> {self.current_limit} (avg usage: {avg_usage:.2f})")
            self.last_adaptation = current_time
    
    def get_stats(self) -> Dict[str, any]:
        """Get current statistics."""
        return {
            "current_limit": self.current_limit,
            "min_limit": self.config.min_limit,
            "max_limit": self.config.max_limit,
            "usage_history": list(self.usage_history),
            "active_keys": len(self.request_counts),
            "total_requests": sum(self.request_counts.values()),
        }
    
    def get_current_limit(self) -> int:
        """Get the current rate limit."""
        return self.current_limit
    
    def get_usage_rate(self) -> float:
        """Get the current usage rate."""
        if not self.usage_history:
            return 0.0
        return self.usage_history[-1]


class ClientAdaptiveRateLimiter:
    """
    Per-client adaptive rate limiter that maintains separate limits for each client.
    """
    
    def __init__(self, config: Optional[AdaptiveConfig] = None):
        """Initialize the client adaptive rate limiter."""
        self.config = config or AdaptiveConfig()
        self.limiters: Dict[str, AdaptiveRateLimiter] = {}
        self._lock = asyncio.Lock()
        self.cleanup_interval = 300.0  # 5 minutes
        self.last_cleanup = time.time()
    
    async def allow(self, client_id: str, key: str = "default") -> bool:
        """
        Check if a request is allowed for the given client and key.
        
        Args:
            client_id: Client identifier
            key: Request key (optional, defaults to "default")
            
        Returns:
            True if request is allowed, False otherwise
        """
        async with self._lock:
            # Get or create limiter for client
            if client_id not in self.limiters:
                self.limiters[client_id] = AdaptiveRateLimiter(self.config)
            
            # Check if cleanup is needed
            await self._cleanup_if_needed()
        
        return await self.limiters[client_id].allow(key)
    
    async def reset(self, client_id: str, key: str = "default") -> None:
        """Reset rate limit for a specific client and key."""
        async with self._lock:
            if client_id in self.limiters:
                await self.limiters[client_id].reset(key)
    
    async def reset_client(self, client_id: str) -> None:
        """Reset all rate limits for a specific client."""
        async with self._lock:
            if client_id in self.limiters:
                del self.limiters[client_id]
    
    async def _cleanup_if_needed(self) -> None:
        """Clean up inactive limiters if needed."""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Remove limiters with no recent activity
        inactive_clients = []
        for client_id, limiter in self.limiters.items():
            if current_time - limiter.last_reset > self.cleanup_interval:
                # Check if limiter has any active requests
                stats = limiter.get_stats()
                if stats["total_requests"] == 0:
                    inactive_clients.append(client_id)
        
        for client_id in inactive_clients:
            del self.limiters[client_id]
        
        self.last_cleanup = current_time
        
        if inactive_clients:
            logger.info(f"Cleaned up {len(inactive_clients)} inactive client rate limiters")
    
    def get_client_stats(self, client_id: str) -> Optional[Dict[str, any]]:
        """Get statistics for a specific client."""
        if client_id in self.limiters:
            return self.limiters[client_id].get_stats()
        return None
    
    def get_all_stats(self) -> Dict[str, Dict[str, any]]:
        """Get statistics for all clients."""
        return {
            client_id: limiter.get_stats()
            for client_id, limiter in self.limiters.items()
        }
    
    def get_active_clients(self) -> List[str]:
        """Get list of active client IDs."""
        return list(self.limiters.keys())


def create_adaptive_limiter(config: Optional[AdaptiveConfig] = None) -> AdaptiveRateLimiter:
    """Factory function to create an adaptive rate limiter."""
    return AdaptiveRateLimiter(config)


def create_client_adaptive_limiter(config: Optional[AdaptiveConfig] = None) -> ClientAdaptiveRateLimiter:
    """Factory function to create a client adaptive rate limiter."""
    return ClientAdaptiveRateLimiter(config)