"""
In-memory token store implementation for GAuth protocol (GiFo-RfC 0111).
Provides a simple memory-based storage backend for development and testing.
"""

from datetime import datetime
from typing import Dict, List, Set
import asyncio
import threading
import time

from .types import TokenMetadata, TokenStore, StorageError, TokenNotFoundError, StorageStats, StorageStatus


class MemoryTokenStore(TokenStore):
    """
    In-memory token store implementation.
    
    This implementation stores all tokens in memory and is suitable for:
    - Development and testing
    - Single-instance deployments
    - Scenarios where token persistence is not required
    
    Note: All data is lost when the process terminates.
    """
    
    def __init__(self):
        # Token storage: token_string -> TokenMetadata
        self._tokens: Dict[str, TokenMetadata] = {}
        
        # Token ID to token string mapping
        self._id_to_token: Dict[str, str] = {}
        
        # Subject to token IDs mapping
        self._subject_tokens: Dict[str, Set[str]] = {}
        
        # Thread lock for thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._start_time = time.time()
        self._operations_count = 0
        self._error_count = 0

    async def store(self, token: str, metadata: TokenMetadata) -> None:
        """Store a token with its metadata."""
        try:
            with self._lock:
                # Store the token
                self._tokens[token] = metadata
                
                # Update ID mapping
                self._id_to_token[metadata.id] = token
                
                # Update subject mapping
                if metadata.subject not in self._subject_tokens:
                    self._subject_tokens[metadata.subject] = set()
                self._subject_tokens[metadata.subject].add(metadata.id)
                
                self._operations_count += 1
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("store", token, f"Failed to store token: {str(e)}", e)

    async def get(self, token: str) -> TokenMetadata:
        """Retrieve token metadata by token string."""
        try:
            with self._lock:
                if token not in self._tokens:
                    raise TokenNotFoundError("get", token, "Token not found")
                
                metadata = self._tokens[token]
                self._operations_count += 1
                
                return metadata
                
        except TokenNotFoundError:
            raise
        except Exception as e:
            self._error_count += 1
            raise StorageError("get", token, f"Failed to retrieve token: {str(e)}", e)

    async def get_by_id(self, token_id: str) -> TokenMetadata:
        """Retrieve token metadata by token ID."""
        try:
            with self._lock:
                if token_id not in self._id_to_token:
                    raise TokenNotFoundError("get_by_id", token_id, "Token ID not found")
                
                token = self._id_to_token[token_id]
                metadata = self._tokens[token]
                self._operations_count += 1
                
                return metadata
                
        except TokenNotFoundError:
            raise
        except Exception as e:
            self._error_count += 1
            raise StorageError("get_by_id", token_id, f"Failed to retrieve token by ID: {str(e)}", e)

    async def delete(self, token: str) -> bool:
        """Remove a token from storage."""
        try:
            with self._lock:
                if token not in self._tokens:
                    return False
                
                metadata = self._tokens[token]
                
                # Remove from main storage
                del self._tokens[token]
                
                # Remove from ID mapping
                if metadata.id in self._id_to_token:
                    del self._id_to_token[metadata.id]
                
                # Remove from subject mapping
                if metadata.subject in self._subject_tokens:
                    self._subject_tokens[metadata.subject].discard(metadata.id)
                    if not self._subject_tokens[metadata.subject]:
                        del self._subject_tokens[metadata.subject]
                
                self._operations_count += 1
                return True
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("delete", token, f"Failed to delete token: {str(e)}", e)

    async def list_by_subject(self, subject: str) -> List[TokenMetadata]:
        """Return all tokens for a subject."""
        try:
            with self._lock:
                if subject not in self._subject_tokens:
                    return []
                
                tokens = []
                for token_id in self._subject_tokens[subject]:
                    if token_id in self._id_to_token:
                        token = self._id_to_token[token_id]
                        if token in self._tokens:
                            tokens.append(self._tokens[token])
                
                self._operations_count += 1
                return tokens
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("list_by_subject", subject, f"Failed to list tokens for subject: {str(e)}", e)

    async def revoke(self, token: str, reason: str = "") -> bool:
        """Mark a token as revoked."""
        try:
            with self._lock:
                if token not in self._tokens:
                    return False
                
                metadata = self._tokens[token]
                metadata.status = "revoked"
                metadata.revoked_at = datetime.now()
                metadata.revocation_reason = reason
                
                self._operations_count += 1
                return True
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("revoke", token, f"Failed to revoke token: {str(e)}", e)

    async def is_revoked(self, token: str) -> bool:
        """Check if a token is revoked."""
        try:
            metadata = await self.get(token)
            return metadata.is_revoked()
            
        except TokenNotFoundError:
            raise
        except Exception as e:
            self._error_count += 1
            raise StorageError("is_revoked", token, f"Failed to check revocation status: {str(e)}", e)

    async def cleanup_expired(self) -> int:
        """Remove expired tokens from storage."""
        try:
            with self._lock:
                now = datetime.now()
                expired_tokens = []
                
                for token, metadata in self._tokens.items():
                    if metadata.expires_at <= now:
                        expired_tokens.append(token)
                
                # Remove expired tokens
                for token in expired_tokens:
                    await self.delete(token)
                
                self._operations_count += 1
                return len(expired_tokens)
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("cleanup_expired", "", f"Failed to cleanup expired tokens: {str(e)}", e)

    async def update_last_used(self, token: str) -> None:
        """Update the last used timestamp for a token."""
        try:
            with self._lock:
                if token not in self._tokens:
                    raise TokenNotFoundError("update_last_used", token, "Token not found")
                
                metadata = self._tokens[token]
                metadata.last_used_at = datetime.now()
                metadata.use_count += 1
                
                self._operations_count += 1
                
        except TokenNotFoundError:
            raise
        except Exception as e:
            self._error_count += 1
            raise StorageError("update_last_used", token, f"Failed to update last used: {str(e)}", e)

    async def get_stats(self) -> StorageStats:
        """Get storage statistics."""
        try:
            with self._lock:
                now = datetime.now()
                total_tokens = len(self._tokens)
                active_tokens = 0
                expired_tokens = 0
                revoked_tokens = 0
                
                for metadata in self._tokens.values():
                    if metadata.is_revoked():
                        revoked_tokens += 1
                    elif metadata.is_expired():
                        expired_tokens += 1
                    else:
                        active_tokens += 1
                
                # Estimate storage size (rough approximation)
                storage_size = sum(
                    len(token) + len(str(metadata.to_dict()))
                    for token, metadata in self._tokens.items()
                )
                
                return StorageStats(
                    total_tokens=total_tokens,
                    active_tokens=active_tokens,
                    expired_tokens=expired_tokens,
                    revoked_tokens=revoked_tokens,
                    storage_size_bytes=storage_size,
                    uptime_seconds=time.time() - self._start_time,
                    operations_count=self._operations_count,
                    error_count=self._error_count
                )
                
        except Exception as e:
            self._error_count += 1
            raise StorageError("get_stats", "", f"Failed to get statistics: {str(e)}", e)

    async def health_check(self) -> StorageStatus:
        """Check the health of the storage backend."""
        try:
            # For memory store, we're healthy if we can access our data structures
            with self._lock:
                # Simple check - access the main data structures
                _ = len(self._tokens)
                _ = len(self._id_to_token)
                _ = len(self._subject_tokens)
                
                return StorageStatus.HEALTHY
                
        except Exception:
            return StorageStatus.UNHEALTHY

    async def close(self) -> None:
        """Close the storage connection and cleanup resources."""
        try:
            with self._lock:
                # Clear all data structures
                self._tokens.clear()
                self._id_to_token.clear()
                self._subject_tokens.clear()
                
        except Exception as e:
            raise StorageError("close", "", f"Failed to close storage: {str(e)}", e)

    # Memory-specific methods
    def clear_all(self) -> None:
        """Clear all stored tokens. Useful for testing."""
        with self._lock:
            self._tokens.clear()
            self._id_to_token.clear()
            self._subject_tokens.clear()

    def get_token_count(self) -> int:
        """Get the current number of stored tokens."""
        with self._lock:
            return len(self._tokens)

    def get_subject_count(self) -> int:
        """Get the number of unique subjects with tokens."""
        with self._lock:
            return len(self._subject_tokens)