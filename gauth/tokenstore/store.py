"""
Token storage types and interfaces for GAuth.

This module provides the core token storage functionality including
token data structures, storage interfaces, and base implementations.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum

from ..common.utils import get_current_time, generate_id


logger = logging.getLogger(__name__)


class TokenStatus(Enum):
    """Token status enumeration."""
    
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


@dataclass
class TokenData:
    """
    Token data structure containing all token information.
    
    This represents the data associated with a token including
    validation status, expiration, ownership, and scopes.
    """
    
    valid: bool = True
    valid_until: datetime = field(default_factory=lambda: get_current_time() + timedelta(hours=1))
    client_id: str = ""
    owner_id: str = ""
    scope: List[str] = field(default_factory=list)
    token_type: str = "bearer"
    issued_at: datetime = field(default_factory=get_current_time)
    audience: List[str] = field(default_factory=list)
    issuer: str = ""
    subject: str = ""
    not_before: Optional[datetime] = None
    jti: str = field(default_factory=generate_id)  # JWT ID
    status: TokenStatus = TokenStatus.VALID
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.subject and self.owner_id:
            self.subject = self.owner_id
        
        if not self.jti:
            self.jti = generate_id()
    
    def is_valid(self) -> bool:
        """
        Check if token is currently valid.
        
        Returns:
            True if token is valid, False otherwise
        """
        now = get_current_time()
        
        # Check basic validity
        if not self.valid or self.status != TokenStatus.VALID:
            return False
        
        # Check expiration
        if now >= self.valid_until:
            return False
        
        # Check not before time
        if self.not_before and now < self.not_before:
            return False
        
        return True
    
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return get_current_time() >= self.valid_until
    
    def time_until_expiry(self) -> timedelta:
        """Get time until token expires."""
        return self.valid_until - get_current_time()
    
    def extend_validity(self, duration: timedelta) -> None:
        """
        Extend token validity.
        
        Args:
            duration: Duration to extend validity
        """
        self.valid_until += duration
    
    def revoke(self) -> None:
        """Revoke the token."""
        self.valid = False
        self.status = TokenStatus.REVOKED
    
    def has_scope(self, required_scope: str) -> bool:
        """
        Check if token has required scope.
        
        Args:
            required_scope: Required scope
            
        Returns:
            True if token has scope, False otherwise
        """
        return required_scope in self.scope
    
    def has_any_scope(self, required_scopes: List[str]) -> bool:
        """
        Check if token has any of the required scopes.
        
        Args:
            required_scopes: List of required scopes
            
        Returns:
            True if token has any scope, False otherwise
        """
        return any(scope in self.scope for scope in required_scopes)
    
    def has_all_scopes(self, required_scopes: List[str]) -> bool:
        """
        Check if token has all required scopes.
        
        Args:
            required_scopes: List of required scopes
            
        Returns:
            True if token has all scopes, False otherwise
        """
        return all(scope in self.scope for scope in required_scopes)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert token data to dictionary.
        
        Returns:
            Dictionary representation
        """
        data = asdict(self)
        
        # Convert datetime objects to ISO format
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif key == "status":
                data[key] = value.value
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenData':
        """
        Create TokenData from dictionary.
        
        Args:
            data: Dictionary data
            
        Returns:
            TokenData instance
        """
        # Convert datetime strings back to datetime objects
        if 'valid_until' in data and isinstance(data['valid_until'], str):
            data['valid_until'] = datetime.fromisoformat(data['valid_until'])
        
        if 'issued_at' in data and isinstance(data['issued_at'], str):
            data['issued_at'] = datetime.fromisoformat(data['issued_at'])
        
        if 'not_before' in data and isinstance(data['not_before'], str):
            data['not_before'] = datetime.fromisoformat(data['not_before'])
        
        if 'status' in data and isinstance(data['status'], str):
            data['status'] = TokenStatus(data['status'])
        
        return cls(**data)
    
    def to_json(self) -> str:
        """
        Convert token data to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TokenData':
        """
        Create TokenData from JSON string.
        
        Args:
            json_str: JSON string
            
        Returns:
            TokenData instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)


class TokenStore(ABC):
    """
    Abstract base class for token storage implementations.
    
    All token store implementations must be safe for concurrent use
    and provide the basic CRUD operations for token management.
    """
    
    @abstractmethod
    async def store(self, token: str, data: TokenData) -> None:
        """
        Store a token with its associated data.
        
        Args:
            token: Token string
            data: Token data
            
        Raises:
            Exception: If storage fails
        """
        pass
    
    @abstractmethod
    async def get(self, token: str) -> Optional[TokenData]:
        """
        Retrieve token data for a given token.
        
        Args:
            token: Token string
            
        Returns:
            TokenData if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def delete(self, token: str) -> bool:
        """
        Remove a token from the store.
        
        Args:
            token: Token string
            
        Returns:
            True if token was deleted, False if not found
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> int:
        """
        Remove expired tokens from the store.
        
        Returns:
            Number of tokens cleaned up
        """
        pass
    
    async def exists(self, token: str) -> bool:
        """
        Check if a token exists in the store.
        
        Args:
            token: Token string
            
        Returns:
            True if token exists, False otherwise
        """
        data = await self.get(token)
        return data is not None
    
    async def is_valid(self, token: str) -> bool:
        """
        Check if a token is valid.
        
        Args:
            token: Token string
            
        Returns:
            True if token is valid, False otherwise
        """
        data = await self.get(token)
        return data is not None and data.is_valid()
    
    async def revoke(self, token: str) -> bool:
        """
        Revoke a token.
        
        Args:
            token: Token string
            
        Returns:
            True if token was revoked, False if not found
        """
        data = await self.get(token)
        if data:
            data.revoke()
            await self.store(token, data)
            return True
        return False
    
    async def extend_token(self, token: str, duration: timedelta) -> bool:
        """
        Extend token validity.
        
        Args:
            token: Token string
            duration: Duration to extend
            
        Returns:
            True if token was extended, False if not found
        """
        data = await self.get(token)
        if data:
            data.extend_validity(duration)
            await self.store(token, data)
            return True
        return False
    
    async def get_tokens_by_client(self, client_id: str) -> List[Tuple[str, TokenData]]:
        """
        Get all tokens for a client.
        
        Args:
            client_id: Client ID
            
        Returns:
            List of (token, data) tuples
        """
        # Default implementation - subclasses can optimize
        return []
    
    async def get_tokens_by_owner(self, owner_id: str) -> List[Tuple[str, TokenData]]:
        """
        Get all tokens for an owner.
        
        Args:
            owner_id: Owner ID
            
        Returns:
            List of (token, data) tuples
        """
        # Default implementation - subclasses can optimize
        return []
    
    async def count_tokens(self) -> int:
        """
        Count total number of tokens.
        
        Returns:
            Number of tokens
        """
        # Default implementation - subclasses can optimize
        return 0
    
    async def count_valid_tokens(self) -> int:
        """
        Count number of valid tokens.
        
        Returns:
            Number of valid tokens
        """
        # Default implementation - subclasses can optimize
        return 0


class TokenStoreError(Exception):
    """Base exception for token store errors."""
    pass


class TokenNotFoundError(TokenStoreError):
    """Exception raised when a token is not found."""
    pass


class TokenExpiredError(TokenStoreError):
    """Exception raised when a token is expired."""
    pass


class TokenInvalidError(TokenStoreError):
    """Exception raised when a token is invalid."""
    pass


def create_token_data(client_id: str,
                     owner_id: str,
                     scopes: List[str],
                     validity_duration: timedelta = timedelta(hours=1),
                     **kwargs) -> TokenData:
    """
    Create a new TokenData instance with common parameters.
    
    Args:
        client_id: Client ID
        owner_id: Owner ID
        scopes: List of scopes
        validity_duration: Token validity duration
        **kwargs: Additional token parameters
        
    Returns:
        TokenData instance
    """
    now = get_current_time()
    
    return TokenData(
        valid=True,
        valid_until=now + validity_duration,
        client_id=client_id,
        owner_id=owner_id,
        scope=scopes,
        issued_at=now,
        subject=owner_id,
        **kwargs
    )


def create_bearer_token(client_id: str,
                       owner_id: str,
                       scopes: List[str],
                       validity_duration: timedelta = timedelta(hours=1)) -> TokenData:
    """
    Create a bearer token.
    
    Args:
        client_id: Client ID
        owner_id: Owner ID  
        scopes: List of scopes
        validity_duration: Token validity duration
        
    Returns:
        TokenData instance
    """
    return create_token_data(
        client_id=client_id,
        owner_id=owner_id,
        scopes=scopes,
        validity_duration=validity_duration,
        token_type="bearer"
    )


def create_refresh_token(client_id: str,
                        owner_id: str,
                        validity_duration: timedelta = timedelta(days=30)) -> TokenData:
    """
    Create a refresh token.
    
    Args:
        client_id: Client ID
        owner_id: Owner ID
        validity_duration: Token validity duration
        
    Returns:
        TokenData instance
    """
    return create_token_data(
        client_id=client_id,
        owner_id=owner_id,
        scopes=["refresh"],
        validity_duration=validity_duration,
        token_type="refresh"
    )