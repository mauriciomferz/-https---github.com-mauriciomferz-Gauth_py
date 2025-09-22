"""
Enhanced error handling for GAuth protocol.

RFC 0111 (GAuth) Compliance Notice:
  - This file is part of a GAuth implementation and must comply with GiFo-RfC 0111 (September 2025).
  - License: Apache 2.0 (OAuth, OpenID Connect), MIT (MCP), Gimel Foundation legal provisions apply.
  - Exclusion Enforcement: This implementation does NOT use Web3/blockchain, DNA/genetic identity, or AI lifecycle control as per RFC 0111 exclusions.
  - For full legal and compliance details, see the LICENSE file and RFC 0111 documentation.
  - No decentralized authorization or excluded technologies are present in this file.
"""

from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


class ErrorCode(Enum):
    """Structured error codes for GAuth protocol."""
    
    # Token related errors
    TOKEN_EXPIRED = "token_expired"
    INVALID_TOKEN = "invalid_token"
    TOKEN_NOT_FOUND = "token_not_found"
    TOKEN_REVOKED = "token_revoked"
    
    # Authorization errors
    INSUFFICIENT_SCOPE = "insufficient_scope"
    INVALID_SCOPE = "invalid_scope"
    AUTHORIZATION_DENIED = "authorization_denied"
    INVALID_GRANT = "invalid_grant"
    
    # Client errors
    INVALID_CLIENT = "invalid_client"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    INVALID_REQUEST = "invalid_request"
    
    # Rate limiting errors
    RATE_LIMITED = "rate_limited"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # Server errors
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    SERVICE_UNAVAILABLE = "service_unavailable"
    
    # Validation errors
    MISSING_PARAMETER = "missing_parameter"
    INVALID_PARAMETER = "invalid_parameter"
    VALIDATION_FAILED = "validation_failed"
    
    # Store/Storage errors
    MISSING_ENCRYPTION_KEY = "missing_encryption_key"
    MISSING_USER_ID = "missing_user_id"
    MISSING_CLIENT_ID = "missing_client_id"
    MISSING_EXPIRY = "missing_expiry"
    STORAGE_ERROR = "storage_error"
    
    # Transaction errors
    TRANSACTION_FAILED = "transaction_failed"
    TRANSACTION_TIMEOUT = "transaction_timeout"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    
    # Network/Communication errors
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    CONNECTION_FAILED = "connection_failed"


class ErrorSource(Enum):
    """Sources where errors can originate."""
    
    CLIENT = "client"
    SERVER = "server"
    NETWORK = "network"
    STORAGE = "storage"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TOKEN_STORE = "token_store"
    RATE_LIMITER = "rate_limiter"
    AUDIT_LOGGER = "audit_logger"
    TRANSACTION = "transaction"


class ErrorSeverity(Enum):
    """Error severity levels."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Additional context for errors."""
    
    request_id: Optional[str] = None
    client_id: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    timestamp: datetime = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.metadata is None:
            self.metadata = {}


class GAuthError(Exception):
    """
    Base exception class for all GAuth errors.
    
    Provides structured error information with error codes,
    sources, severity levels, and additional context.
    """
    
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        source: ErrorSource = ErrorSource.SERVER,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        self.code = code
        self.message = message
        self.source = source
        self.severity = severity
        self.context = context or ErrorContext()
        self.cause = cause
        
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        result = {
            "error": self.code.value,
            "error_description": self.message,
            "error_source": self.source.value,
            "error_severity": self.severity.value,
            "timestamp": self.context.timestamp.isoformat(),
        }
        
        if self.context.request_id:
            result["request_id"] = self.context.request_id
        
        if self.context.client_id:
            result["client_id"] = self.context.client_id
        
        if self.context.metadata:
            result["metadata"] = self.context.metadata
        
        if self.cause:
            result["caused_by"] = str(self.cause)
        
        return result
    
    def is_client_error(self) -> bool:
        """Check if this is a client-side error."""
        return self.source == ErrorSource.CLIENT or self.code in [
            ErrorCode.INVALID_REQUEST,
            ErrorCode.INVALID_CLIENT,
            ErrorCode.UNAUTHORIZED_CLIENT,
            ErrorCode.INVALID_SCOPE,
            ErrorCode.INSUFFICIENT_SCOPE,
        ]
    
    def is_server_error(self) -> bool:
        """Check if this is a server-side error."""
        return self.source == ErrorSource.SERVER or self.code in [
            ErrorCode.SERVER_ERROR,
            ErrorCode.TEMPORARILY_UNAVAILABLE,
            ErrorCode.SERVICE_UNAVAILABLE,
        ]
    
    def is_retryable(self) -> bool:
        """Check if this error might be resolved by retrying."""
        return self.code in [
            ErrorCode.RATE_LIMITED,
            ErrorCode.TEMPORARILY_UNAVAILABLE,
            ErrorCode.SERVICE_UNAVAILABLE,
            ErrorCode.NETWORK_ERROR,
            ErrorCode.TIMEOUT,
            ErrorCode.CONNECTION_FAILED,
        ]


class TokenError(GAuthError):
    """Errors related to token operations."""
    
    def __init__(self, code: ErrorCode, message: str, token_id: Optional[str] = None, **kwargs):
        context = kwargs.pop("context", ErrorContext())
        if token_id:
            context.metadata["token_id"] = token_id
        
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.TOKEN_STORE,
            context=context,
            **kwargs
        )


class AuthorizationError(GAuthError):
    """Errors related to authorization operations."""
    
    def __init__(self, code: ErrorCode, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.AUTHORIZATION,
            **kwargs
        )


class ValidationError(GAuthError):
    """Errors related to input validation."""
    
    def __init__(self, code: ErrorCode, message: str, field: Optional[str] = None, **kwargs):
        context = kwargs.pop("context", ErrorContext())
        if field:
            context.metadata["field"] = field
        
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.VALIDATION,
            context=context,
            **kwargs
        )


class RateLimitError(GAuthError):
    """Errors related to rate limiting."""
    
    def __init__(self, message: str = "Rate limit exceeded", **kwargs):
        super().__init__(
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message=message,
            source=ErrorSource.RATE_LIMITER,
            **kwargs
        )


class TransactionError(GAuthError):
    """Errors related to transaction processing."""
    
    def __init__(self, code: ErrorCode, message: str, transaction_id: Optional[str] = None, **kwargs):
        context = kwargs.pop("context", ErrorContext())
        if transaction_id:
            context.metadata["transaction_id"] = transaction_id
        
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.TRANSACTION,
            context=context,
            **kwargs
        )


class StorageError(GAuthError):
    """Errors related to storage operations."""
    
    def __init__(self, code: ErrorCode, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.STORAGE,
            **kwargs
        )


class NetworkError(GAuthError):
    """Errors related to network operations."""
    
    def __init__(self, code: ErrorCode, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            source=ErrorSource.NETWORK,
            **kwargs
        )


# Error utility functions
def create_validation_error(message: str, field: Optional[str] = None) -> ValidationError:
    """Create a validation error."""
    return ValidationError(
        code=ErrorCode.VALIDATION_FAILED,
        message=message,
        field=field
    )

def create_token_error(message: str, token_id: Optional[str] = None) -> TokenError:
    """Create a token error."""
    return TokenError(
        code=ErrorCode.INVALID_TOKEN,
        message=message,
        token_id=token_id
    )

def create_authorization_error(message: str) -> AuthorizationError:
    """Create an authorization error."""
    return AuthorizationError(
        code=ErrorCode.AUTHORIZATION_DENIED,
        message=message
    )

def create_rate_limit_error(message: str = "Rate limit exceeded") -> RateLimitError:
    """Create a rate limit error."""
    return RateLimitError(message=message)

def wrap_exception(exc: Exception, code: ErrorCode, message: str) -> GAuthError:
    """Wrap a generic exception as a GAuth error."""
    return GAuthError(
        code=code,
        message=message,
        cause=exc
    )

# Error handler decorator
def handle_errors(error_map: Dict[type, ErrorCode] = None):
    """
    Decorator to handle exceptions and convert them to GAuth errors.
    
    Args:
        error_map: Mapping of exception types to error codes
    """
    if error_map is None:
        error_map = {
            ValueError: ErrorCode.INVALID_PARAMETER,
            KeyError: ErrorCode.MISSING_PARAMETER,
            TimeoutError: ErrorCode.TIMEOUT,
            ConnectionError: ErrorCode.CONNECTION_FAILED,
        }
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except GAuthError:
                # Re-raise GAuth errors as-is
                raise
            except Exception as e:
                # Convert other exceptions to GAuth errors
                error_code = error_map.get(type(e), ErrorCode.SERVER_ERROR)
                raise wrap_exception(e, error_code, str(e))
        
        return wrapper
    return decorator


# Error collection for multiple validation errors
class ErrorCollection:
    """Collection of multiple errors."""
    
    def __init__(self):
        self.errors: List[GAuthError] = []
    
    def add(self, error: GAuthError):
        """Add an error to the collection."""
        self.errors.append(error)
    
    def add_validation_error(self, message: str, field: Optional[str] = None):
        """Add a validation error."""
        self.add(create_validation_error(message, field))
    
    def has_errors(self) -> bool:
        """Check if collection has any errors."""
        return len(self.errors) > 0
    
    def get_errors(self) -> List[GAuthError]:
        """Get all errors."""
        return self.errors.copy()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "errors": [error.to_dict() for error in self.errors],
            "error_count": len(self.errors)
        }
    
    def raise_if_errors(self):
        """Raise the first error if any exist."""
        if self.has_errors():
            raise self.errors[0]