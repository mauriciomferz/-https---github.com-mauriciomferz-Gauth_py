"""
PoA-specific errors for the GAuth protocol (GiFo-RfC 115).
Implements error handling for Power-of-Attorney operations.
"""

from typing import Optional, Any


class PoAError(Exception):
    """Base class for Power-of-Attorney related errors."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None, 
                 error_code: Optional[str] = None):
        self.message = message
        self.poa_id = poa_id
        self.error_code = error_code
        super().__init__(message)


class PoAValidationError(PoAError):
    """Raised when PoA validation fails."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None, 
                 validation_errors: Optional[list] = None):
        self.validation_errors = validation_errors or []
        super().__init__(message, poa_id, "POA_VALIDATION_ERROR")


class PoAAuthorizationError(PoAError):
    """Raised when PoA authorization check fails."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None,
                 requested_action: Optional[str] = None):
        self.requested_action = requested_action
        super().__init__(message, poa_id, "POA_AUTHORIZATION_ERROR")


class PoADelegationError(PoAError):
    """Raised when PoA delegation operation fails."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None,
                 delegation_target: Optional[str] = None):
        self.delegation_target = delegation_target
        super().__init__(message, poa_id, "POA_DELEGATION_ERROR")


class PoAExpirationError(PoAError):
    """Raised when PoA has expired."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None,
                 expiration_date: Optional[str] = None):
        self.expiration_date = expiration_date
        super().__init__(message, poa_id, "POA_EXPIRATION_ERROR")


class PoARevocationError(PoAError):
    """Raised when PoA has been revoked."""
    
    def __init__(self, message: str, poa_id: Optional[str] = None,
                 revocation_reason: Optional[str] = None):
        self.revocation_reason = revocation_reason
        super().__init__(message, poa_id, "POA_REVOCATION_ERROR")


class PrincipalVerificationError(PoAError):
    """Raised when principal verification fails."""
    
    def __init__(self, message: str, principal_id: Optional[str] = None,
                 verification_stage: Optional[str] = None):
        self.principal_id = principal_id
        self.verification_stage = verification_stage
        super().__init__(message, None, "PRINCIPAL_VERIFICATION_ERROR")


class ClientRegistrationError(PoAError):
    """Raised when client registration fails."""
    
    def __init__(self, message: str, client_id: Optional[str] = None,
                 registration_issue: Optional[str] = None):
        self.client_id = client_id
        self.registration_issue = registration_issue
        super().__init__(message, None, "CLIENT_REGISTRATION_ERROR")