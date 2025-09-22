"""
Authentication error classes for GAuth.
"""


class AuthError(Exception):
    """Base authentication error."""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "AUTH_ERROR"
        self.details = details or {}


class TokenError(AuthError):
    """Token-related error."""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message, error_code or "TOKEN_ERROR", details)


class ValidationError(AuthError):
    """Validation error."""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message, error_code or "VALIDATION_ERROR", details)


class CredentialError(AuthError):
    """Credential error."""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message, error_code or "CREDENTIAL_ERROR", details)


class ExpiredTokenError(TokenError):
    """Token has expired."""
    
    def __init__(self, message: str = "Token has expired", details: dict = None):
        super().__init__(message, "EXPIRED_TOKEN", details)


class InvalidTokenError(TokenError):
    """Token is invalid."""
    
    def __init__(self, message: str = "Token is invalid", details: dict = None):
        super().__init__(message, "INVALID_TOKEN", details)


class UnsupportedAuthTypeError(AuthError):
    """Unsupported authentication type."""
    
    def __init__(self, auth_type: str, details: dict = None):
        message = f"Unsupported authentication type: {auth_type}"
        super().__init__(message, "UNSUPPORTED_AUTH_TYPE", details)