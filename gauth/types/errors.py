"""
Error types and error codes for GAuth protocol.
Provides structured error handling across all packages.
"""

from enum import Enum
from typing import Dict, Any, Optional


class ErrorCode(str, Enum):
    """Standard error codes used across GAuth."""
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    VALIDATION_FAILED = "validation_failed"
    CONFIGURATION_ERROR = "configuration_error"
    SECURITY_VIOLATION = "security_violation"
    
    def __str__(self) -> str:
        return self.value


# Error code constants for easy import
INVALID_REQUEST = ErrorCode.INVALID_REQUEST
UNAUTHORIZED = ErrorCode.UNAUTHORIZED
FORBIDDEN = ErrorCode.FORBIDDEN
NOT_FOUND = ErrorCode.NOT_FOUND
TIMEOUT = ErrorCode.TIMEOUT
RATE_LIMITED = ErrorCode.RATE_LIMITED
INTERNAL_ERROR = ErrorCode.INTERNAL_ERROR
SERVICE_UNAVAILABLE = ErrorCode.SERVICE_UNAVAILABLE
VALIDATION_FAILED = ErrorCode.VALIDATION_FAILED
CONFIGURATION_ERROR = ErrorCode.CONFIGURATION_ERROR
SECURITY_VIOLATION = ErrorCode.SECURITY_VIOLATION


class GAuthError(Exception):
    """Base exception for all GAuth-related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = INTERNAL_ERROR,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.cause = cause
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        result = {
            'error': self.error_code.value,
            'message': self.message,
            'details': self.details
        }
        
        if self.cause:
            result['cause'] = str(self.cause)
        
        return result
    
    def __str__(self) -> str:
        return f"{self.error_code.value}: {self.message}"


class ValidationError(GAuthError):
    """Raised when validation fails."""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, VALIDATION_FAILED, details)
        self.field = field
        self.value = value
        
        if field:
            self.details['field'] = field
        if value is not None:
            self.details['value'] = str(value)


class ConfigurationError(GAuthError):
    """Raised when there's a configuration error."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, CONFIGURATION_ERROR, details)
        self.config_key = config_key
        self.config_value = config_value
        
        if config_key:
            self.details['config_key'] = config_key
        if config_value is not None:
            self.details['config_value'] = str(config_value)


class SecurityError(GAuthError):
    """Raised when there's a security violation."""
    
    def __init__(
        self,
        message: str,
        security_context: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, SECURITY_VIOLATION, details)
        self.security_context = security_context or {}
        self.details.update(self.security_context)


class RateLimitError(GAuthError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str,
        limit: Optional[int] = None,
        window: Optional[str] = None,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, RATE_LIMITED, details)
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        
        if limit:
            self.details['limit'] = limit
        if window:
            self.details['window'] = window
        if retry_after:
            self.details['retry_after'] = retry_after


class TimeoutError(GAuthError):
    """Raised when an operation times out."""
    
    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, TIMEOUT, details)
        self.timeout_seconds = timeout_seconds
        self.operation = operation
        
        if timeout_seconds:
            self.details['timeout_seconds'] = timeout_seconds
        if operation:
            self.details['operation'] = operation


class ServiceUnavailableError(GAuthError):
    """Raised when a service is unavailable."""
    
    def __init__(
        self,
        message: str,
        service_name: Optional[str] = None,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, SERVICE_UNAVAILABLE, details)
        self.service_name = service_name
        self.retry_after = retry_after
        
        if service_name:
            self.details['service_name'] = service_name
        if retry_after:
            self.details['retry_after'] = retry_after


# Error mapping for HTTP status codes
ERROR_CODE_TO_HTTP_STATUS = {
    INVALID_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    TIMEOUT: 408,
    RATE_LIMITED: 429,
    INTERNAL_ERROR: 500,
    SERVICE_UNAVAILABLE: 503,
    VALIDATION_FAILED: 422,
    CONFIGURATION_ERROR: 500,
    SECURITY_VIOLATION: 403,
}


def get_http_status(error_code: ErrorCode) -> int:
    """Get HTTP status code for an error code."""
    return ERROR_CODE_TO_HTTP_STATUS.get(error_code, 500)


def create_error_response(error: GAuthError) -> Dict[str, Any]:
    """Create a standardized error response."""
    return {
        'error': error.error_code.value,
        'message': error.message,
        'details': error.details,
        'http_status': get_http_status(error.error_code)
    }