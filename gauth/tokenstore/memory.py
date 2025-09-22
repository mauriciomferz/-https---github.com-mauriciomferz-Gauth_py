"""
In-memory token storage implementation for GAuth.

This module provides a thread-safe in-memory token store
suitable for development and single-instance deployments.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from .store import TokenStore, TokenData, get_current_time


logger = logging.getLogger(__name__)


class MemoryTokenStore(TokenStore):
    """
    In-memory token store implementation.
    
    This implementation uses a simple dictionary to store tokens
    in memory with proper locking for thread safety.
    """
    
    def __init__(self, cleanup_interval: int = 300):
        """
        Initialize memory token store.
        
        Args:
            cleanup_interval: Automatic cleanup interval in seconds
        """
        self._store: Dict[str, TokenData] = {}
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the cleanup task."""
        if not self._running:
            self._running = True
            self._cleanup_task = asyncio.create_task(self._auto_cleanup())
            logger.info("Started memory token store with auto-cleanup")
    
    async def stop(self) -> None:
        """Stop the cleanup task."""
        if self._running:
            self._running = False
            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
            logger.info("Stopped memory token store")
    
    async def _auto_cleanup(self) -> None:
        """Automatic cleanup task."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                if self._running:
                    cleaned = await self.cleanup()
                    if cleaned > 0:
                        logger.debug(f"Auto-cleanup removed {cleaned} expired tokens")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-cleanup: {e}")
    
    async def store(self, token: str, data: TokenData) -> None:
        """Store a token with its associated data."""
        async with self._lock:
            self._store[token] = data
            logger.debug(f"Stored token for client {data.client_id}")
    
    async def get(self, token: str) -> Optional[TokenData]:
        """Retrieve token data for a given token."""
        async with self._lock:
            data = self._store.get(token)
            
            if data and data.is_expired():
                # Remove expired token
                del self._store[token]
                logger.debug(f"Removed expired token for client {data.client_id}")
                return None
            
            return data
    
    async def delete(self, token: str) -> bool:
        """Remove a token from the store."""
        async with self._lock:
            if token in self._store:
                data = self._store[token]
                del self._store[token]
                logger.debug(f"Deleted token for client {data.client_id}")
                return True
            return False
    
    async def cleanup(self) -> int:
        """Remove expired tokens from the store."""
        async with self._lock:
            now = get_current_time()
            expired_tokens = []
            
            for token, data in self._store.items():
                if not data.valid or data.status.value != "valid" or now >= data.valid_until:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                del self._store[token]
            
            if expired_tokens:
                logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
            
            return len(expired_tokens)
    
    async def exists(self, token: str) -> bool:
        """Check if a token exists in the store."""
        async with self._lock:
            return token in self._store
    
    async def is_valid(self, token: str) -> bool:
        """Check if a token is valid."""
        data = await self.get(token)
        return data is not None and data.is_valid()
    
    async def get_tokens_by_client(self, client_id: str) -> List[Tuple[str, TokenData]]:
        """Get all tokens for a client."""
        async with self._lock:
            tokens = []
            for token, data in self._store.items():
                if data.client_id == client_id:
                    tokens.append((token, data))
            return tokens
    
    async def get_tokens_by_owner(self, owner_id: str) -> List[Tuple[str, TokenData]]:
        """Get all tokens for an owner."""
        async with self._lock:
            tokens = []
            for token, data in self._store.items():
                if data.owner_id == owner_id:
                    tokens.append((token, data))
            return tokens
    
    async def count_tokens(self) -> int:
        """Count total number of tokens."""
        async with self._lock:
            return len(self._store)
    
    async def count_valid_tokens(self) -> int:
        """Count number of valid tokens."""
        async with self._lock:
            count = 0
            for data in self._store.values():
                if data.is_valid():
                    count += 1
            return count
    
    async def get_all_tokens(self) -> List[Tuple[str, TokenData]]:
        """
        Get all tokens in the store.
        
        Returns:
            List of (token, data) tuples
        """
        async with self._lock:
            return list(self._store.items())
    
    async def clear(self) -> int:
        """
        Clear all tokens from the store.
        
        Returns:
            Number of tokens cleared
        """
        async with self._lock:
            count = len(self._store)
            self._store.clear()
            logger.info(f"Cleared {count} tokens from memory store")
            return count
    
    async def get_statistics(self) -> Dict[str, int]:
        """
        Get store statistics.
        
        Returns:
            Dictionary with store statistics
        """
        async with self._lock:
            total_tokens = len(self._store)
            valid_tokens = 0
            expired_tokens = 0
            revoked_tokens = 0
            
            for data in self._store.values():
                if data.is_valid():
                    valid_tokens += 1
                elif data.is_expired():
                    expired_tokens += 1
                elif data.status.value == "revoked":
                    revoked_tokens += 1
            
            return {
                "total_tokens": total_tokens,
                "valid_tokens": valid_tokens,
                "expired_tokens": expired_tokens,
                "revoked_tokens": revoked_tokens
            }
    
    async def get_tokens_expiring_soon(self, threshold: timedelta = timedelta(minutes=5)) -> List[Tuple[str, TokenData]]:
        """
        Get tokens that will expire soon.
        
        Args:
            threshold: Time threshold for "expiring soon"
            
        Returns:
            List of (token, data) tuples
        """
        async with self._lock:
            now = get_current_time()
            expiry_time = now + threshold
            
            expiring_tokens = []
            for token, data in self._store.items():
                if data.is_valid() and data.valid_until <= expiry_time:
                    expiring_tokens.append((token, data))
            
            return expiring_tokens


def create_memory_store(cleanup_interval: int = 300, 
                       auto_start: bool = True) -> MemoryTokenStore:
    """
    Create a memory token store.
    
    Args:
        cleanup_interval: Automatic cleanup interval in seconds
        auto_start: Whether to automatically start cleanup task
        
    Returns:
        MemoryTokenStore instance
    """
    store = MemoryTokenStore(cleanup_interval)
    
    if auto_start:
        # Schedule start for next event loop iteration
        asyncio.create_task(store.start())
    
    return store