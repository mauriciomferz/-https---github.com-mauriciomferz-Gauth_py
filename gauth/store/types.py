"""
Storage types and interfaces for the GAuth protocol (GiFo-RfC 0111).
Defines token storage abstractions and metadata structures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import asyncio


class StorageStatus(Enum):
    """Status of a storage backend."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class TokenMetadata:
    """Metadata about a stored token."""
    id: str
    subject: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    key_id: str = ""
    type: str = "access"
    status: str = "active"
    scopes: List[str] = field(default_factory=list)
    client_id: str = ""
    grant_id: str = ""
    revoked_at: Optional[datetime] = None
    revocation_reason: str = ""
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.now() > self.expires_at

    def is_revoked(self) -> bool:
        """Check if the token has been revoked."""
        return self.status == "revoked" or self.revoked_at is not None

    def is_valid(self) -> bool:
        """Check if the token is valid (not expired or revoked)."""
        return not self.is_expired() and not self.is_revoked()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'subject': self.subject,
            'issuer': self.issuer,
            'issued_at': self.issued_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'key_id': self.key_id,
            'type': self.type,
            'status': self.status,
            'scopes': self.scopes,
            'client_id': self.client_id,
            'grant_id': self.grant_id,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revocation_reason': self.revocation_reason,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'use_count': self.use_count,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenMetadata':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            subject=data['subject'],
            issuer=data['issuer'],
            issued_at=datetime.fromisoformat(data['issued_at']),
            expires_at=datetime.fromisoformat(data['expires_at']),
            key_id=data.get('key_id', ''),
            type=data.get('type', 'access'),
            status=data.get('status', 'active'),
            scopes=data.get('scopes', []),
            client_id=data.get('client_id', ''),
            grant_id=data.get('grant_id', ''),
            revoked_at=datetime.fromisoformat(data['revoked_at']) if data.get('revoked_at') else None,
            revocation_reason=data.get('revocation_reason', ''),
            last_used_at=datetime.fromisoformat(data['last_used_at']) if data.get('last_used_at') else None,
            use_count=data.get('use_count', 0),
            metadata=data.get('metadata', {})
        )


@dataclass 
class StorageStats:
    """Statistics about storage usage."""
    total_tokens: int = 0
    active_tokens: int = 0
    expired_tokens: int = 0
    revoked_tokens: int = 0
    storage_size_bytes: int = 0
    last_cleanup_at: Optional[datetime] = None
    uptime_seconds: float = 0.0
    operations_count: int = 0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_tokens': self.total_tokens,
            'active_tokens': self.active_tokens,
            'expired_tokens': self.expired_tokens,
            'revoked_tokens': self.revoked_tokens,
            'storage_size_bytes': self.storage_size_bytes,
            'last_cleanup_at': self.last_cleanup_at.isoformat() if self.last_cleanup_at else None,
            'uptime_seconds': self.uptime_seconds,
            'operations_count': self.operations_count,
            'error_count': self.error_count
        }


class StorageError(Exception):
    """Base class for storage-related errors."""
    
    def __init__(self, operation: str, key: str = "", message: str = "", 
                 cause: Optional[Exception] = None):
        self.operation = operation
        self.key = key
        self.message = message
        self.cause = cause
        super().__init__(f"Storage error in {operation}: {message}")


class TokenNotFoundError(StorageError):
    """Raised when a token is not found in storage."""
    pass


class TokenExpiredError(StorageError):
    """Raised when a token has expired."""
    pass


class TokenRevokedError(StorageError):
    """Raised when a token has been revoked."""
    pass


class StorageConnectionError(StorageError):
    """Raised when there's a connection issue with the storage backend."""
    pass


class TokenStore(ABC):
    """Abstract base class for token storage backends."""
    
    @abstractmethod
    async def store(self, token: str, metadata: TokenMetadata) -> None:
        """
        Store a token with its metadata.
        
        Args:
            token: The token string to store
            metadata: Token metadata
            
        Raises:
            StorageError: If storage operation fails
        """
        pass

    @abstractmethod
    async def get(self, token: str) -> TokenMetadata:
        """
        Retrieve token metadata by token string.
        
        Args:
            token: The token string to look up
            
        Returns:
            TokenMetadata: The token metadata
            
        Raises:
            TokenNotFoundError: If token is not found
            StorageError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def get_by_id(self, token_id: str) -> TokenMetadata:
        """
        Retrieve token metadata by token ID.
        
        Args:
            token_id: The token ID to look up
            
        Returns:
            TokenMetadata: The token metadata
            
        Raises:
            TokenNotFoundError: If token is not found
            StorageError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def delete(self, token: str) -> bool:
        """
        Remove a token from storage.
        
        Args:
            token: The token string to delete
            
        Returns:
            bool: True if token was deleted, False if not found
            
        Raises:
            StorageError: If deletion operation fails
        """
        pass

    @abstractmethod
    async def list_by_subject(self, subject: str) -> List[TokenMetadata]:
        """
        Return all tokens for a subject.
        
        Args:
            subject: The subject to list tokens for
            
        Returns:
            List[TokenMetadata]: List of token metadata
            
        Raises:
            StorageError: If listing operation fails
        """
        pass

    @abstractmethod
    async def revoke(self, token: str, reason: str = "") -> bool:
        """
        Mark a token as revoked.
        
        Args:
            token: The token string to revoke
            reason: Reason for revocation
            
        Returns:
            bool: True if token was revoked, False if not found
            
        Raises:
            StorageError: If revocation operation fails
        """
        pass

    @abstractmethod
    async def is_revoked(self, token: str) -> bool:
        """
        Check if a token is revoked.
        
        Args:
            token: The token string to check
            
        Returns:
            bool: True if token is revoked
            
        Raises:
            TokenNotFoundError: If token is not found
            StorageError: If check operation fails
        """
        pass

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """
        Remove expired tokens from storage.
        
        Returns:
            int: Number of tokens removed
            
        Raises:
            StorageError: If cleanup operation fails
        """
        pass

    @abstractmethod
    async def update_last_used(self, token: str) -> None:
        """
        Update the last used timestamp for a token.
        
        Args:
            token: The token string to update
            
        Raises:
            TokenNotFoundError: If token is not found
            StorageError: If update operation fails
        """
        pass

    @abstractmethod
    async def get_stats(self) -> StorageStats:
        """
        Get storage statistics.
        
        Returns:
            StorageStats: Storage statistics
            
        Raises:
            StorageError: If stats retrieval fails
        """
        pass

    @abstractmethod
    async def health_check(self) -> StorageStatus:
        """
        Check the health of the storage backend.
        
        Returns:
            StorageStatus: Current health status
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """
        Close the storage connection and cleanup resources.
        """
        pass

    # Optional bulk operations
    async def store_batch(self, tokens: List[tuple[str, TokenMetadata]]) -> None:
        """
        Store multiple tokens in a batch operation.
        Default implementation stores them one by one.
        
        Args:
            tokens: List of (token, metadata) tuples
            
        Raises:
            StorageError: If batch operation fails
        """
        for token, metadata in tokens:
            await self.store(token, metadata)

    async def delete_batch(self, tokens: List[str]) -> int:
        """
        Delete multiple tokens in a batch operation.
        Default implementation deletes them one by one.
        
        Args:
            tokens: List of token strings to delete
            
        Returns:
            int: Number of tokens successfully deleted
            
        Raises:
            StorageError: If batch operation fails
        """
        deleted_count = 0
        for token in tokens:
            if await self.delete(token):
                deleted_count += 1
        return deleted_count

    async def exists(self, token: str) -> bool:
        """
        Check if a token exists in storage.
        
        Args:
            token: The token string to check
            
        Returns:
            bool: True if token exists
        """
        try:
            await self.get(token)
            return True
        except TokenNotFoundError:
            return False