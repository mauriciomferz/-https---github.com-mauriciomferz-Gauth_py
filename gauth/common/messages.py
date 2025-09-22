"""
Common constants, messages, and utilities for GAuth framework.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class ErrorMessages:
    """Error messages for GAuth operations."""
    invalid_token: str = "Token is invalid or expired"
    rate_limit_exceeded: str = "Rate limit exceeded. Please try again later"
    invalid_authentication: str = "Invalid authentication credentials"
    insufficient_scope: str = "Insufficient scope for this operation"
    circuit_breaker_open: str = "Service temporarily unavailable due to high error rate"
    invalid_grant_type: str = "Invalid or unsupported grant type"
    missing_client_id: str = "Client ID is required"
    invalid_client_secret: str = "Invalid client secret"
    service_unavailable: str = "Service is temporarily unavailable"
    invalid_request: str = "Invalid request parameters"
    unauthorized: str = "Authorization required"
    forbidden: str = "Access denied"
    not_found: str = "Resource not found"
    conflict: str = "Resource already exists"
    internal_error: str = "Internal server error"
    timeout: str = "Request timeout"
    too_many_requests: str = "Too many requests"


@dataclass
class InfoMessages:
    """Informational messages for GAuth operations."""
    token_issued: str = "Token successfully issued"
    token_revoked: str = "Token successfully revoked"
    token_refreshed: str = "Token successfully refreshed"
    circuit_breaker_closed: str = "Service has recovered and is accepting requests"
    rate_limit_reset: str = "Rate limit window has reset"
    authorization_granted: str = "Authorization granted"
    authentication_successful: str = "Authentication successful"
    logout_successful: str = "Logout successful"
    service_healthy: str = "Service is healthy"
    service_started: str = "Service started successfully"
    service_stopped: str = "Service stopped successfully"


@dataclass
class ErrorCodes:
    """Error codes for API responses."""
    invalid_token: str = "invalid_token"
    rate_limit_exceeded: str = "rate_limit_exceeded"
    invalid_authentication: str = "invalid_authentication"
    insufficient_scope: str = "insufficient_scope"
    circuit_breaker_open: str = "circuit_breaker_open"
    invalid_grant_type: str = "invalid_grant_type"
    missing_client_id: str = "missing_client_id"
    invalid_client_secret: str = "invalid_client_secret"
    service_unavailable: str = "service_unavailable"
    invalid_request: str = "invalid_request"
    unauthorized: str = "unauthorized"
    forbidden: str = "forbidden"
    not_found: str = "not_found"
    conflict: str = "conflict"
    internal_error: str = "internal_error"
    timeout: str = "timeout"
    too_many_requests: str = "too_many_requests"


# Global instances
MESSAGES = ErrorMessages()
INFO_MESSAGES = InfoMessages()
ERROR_CODES = ErrorCodes()


# Common HTTP status codes
class HTTPStatus:
    """HTTP status codes used in GAuth."""
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


# Common headers
class Headers:
    """Common HTTP headers used in GAuth."""
    AUTHORIZATION = "Authorization"
    CONTENT_TYPE = "Content-Type"
    ACCEPT = "Accept"
    USER_AGENT = "User-Agent"
    X_REQUEST_ID = "X-Request-ID"
    X_CORRELATION_ID = "X-Correlation-ID"
    X_CLIENT_ID = "X-Client-ID"
    X_API_VERSION = "X-API-Version"
    X_RATE_LIMIT_REMAINING = "X-RateLimit-Remaining"
    X_RATE_LIMIT_RESET = "X-RateLimit-Reset"
    X_RATE_LIMIT_LIMIT = "X-RateLimit-Limit"


# Content types
class ContentTypes:
    """Common content types."""
    JSON = "application/json"
    XML = "application/xml"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    TEXT_PLAIN = "text/plain"
    TEXT_HTML = "text/html"


# Default configuration values
class Defaults:
    """Default configuration values."""
    TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
    REFRESH_TOKEN_EXPIRY_SECONDS = 86400 * 7  # 7 days
    RATE_LIMIT_REQUESTS_PER_SECOND = 100
    RATE_LIMIT_BURST_SIZE = 20
    CIRCUIT_BREAKER_ERROR_THRESHOLD = 10
    CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS = 30
    RETRY_MAX_ATTEMPTS = 3
    RETRY_INITIAL_DELAY_SECONDS = 1
    TIMEOUT_SECONDS = 30
    BULKHEAD_MAX_CONCURRENT_REQUESTS = 50
    
    # Audit settings
    AUDIT_BATCH_SIZE = 100
    AUDIT_FLUSH_INTERVAL_SECONDS = 10
    
    # Token settings
    JWT_ALGORITHM = "HS256"
    PASETO_VERSION = "v4"
    
    # Service settings
    SERVICE_DISCOVERY_INTERVAL_SECONDS = 30
    HEALTH_CHECK_INTERVAL_SECONDS = 10
    METRICS_COLLECTION_INTERVAL_SECONDS = 60


# Protocol constants
class Protocols:
    """Protocol constants."""
    GAUTH = "gauth"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openid-connect"
    SAML = "saml"
    LDAP = "ldap"
    PASETO = "paseto"
    JWT = "jwt"


# Grant types
class GrantTypes:
    """OAuth2 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    IMPLICIT = "implicit"
    PASSWORD = "password"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


# Token types
class TokenTypes:
    """Token types used in GAuth."""
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"
    BEARER = "Bearer"
    JWT = "JWT"
    PASETO = "PASETO"


# Scopes
class Scopes:
    """Common scopes for authorization."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    USER = "user"
    PROFILE = "profile"
    EMAIL = "email"
    OPENID = "openid"
    OFFLINE_ACCESS = "offline_access"


# Service types
class ServiceTypes:
    """Service types in the GAuth ecosystem."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TOKEN_SERVICE = "token_service"
    USER_SERVICE = "user_service"
    AUDIT_SERVICE = "audit_service"
    METRICS_SERVICE = "metrics_service"
    NOTIFICATION_SERVICE = "notification_service"


def get_error_response(code: str, message: Optional[str] = None) -> Dict[str, Any]:
    """
    Get standardized error response.
    
    Args:
        code: Error code
        message: Optional custom message
        
    Returns:
        Error response dictionary
    """
    return {
        "error": code,
        "error_description": message or getattr(MESSAGES, code.replace('-', '_'), "Unknown error"),
        "timestamp": None  # Will be set by the caller
    }


def get_success_response(data: Any = None, message: Optional[str] = None) -> Dict[str, Any]:
    """
    Get standardized success response.
    
    Args:
        data: Response data
        message: Optional success message
        
    Returns:
        Success response dictionary
    """
    response = {
        "success": True,
        "timestamp": None  # Will be set by the caller
    }
    
    if data is not None:
        response["data"] = data
    
    if message:
        response["message"] = message
        
    return response