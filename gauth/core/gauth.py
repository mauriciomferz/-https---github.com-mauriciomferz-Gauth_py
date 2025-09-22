"""
Main GAuth implementation for Python.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

GAuth Protocol Compliance: This file implements the GAuth protocol (GiFo-RfC 0111).

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this file (see [GAuth] comments below)
  - OAuth 2.0:      NOT USED anywhere in this file
  - PKCE:           NOT USED anywhere in this file
  - OpenID:         NOT USED anywhere in this file

[GAuth] = GAuth protocol logic (GiFo-RfC 0111)
[Other] = Placeholder for OAuth2, OpenID, PKCE, or other protocols (none present in this file)
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import asyncio
import logging

from .config import Config
from .types import (
    AuthorizationRequest,
    AuthorizationGrant,
    TokenRequest,
    TokenResponse,
    AccessToken,
    Transaction,
    TransactionResult,
    AuditEvent,
    GAuthError,
    AuthorizationError,
    TokenError,
    ValidationError,
    RateLimitError,
    TransactionError,
)
from ..audit.logger import AuditLogger, MemoryAuditLogger
from ..token.store import TokenStore, MemoryTokenStore
from ..ratelimit.limiter import RateLimiter, TokenBucketRateLimiter


class GAuth:
    """
    Main authentication and authorization system for the GAuth protocol (GiFo-RfC 0111).
    Use GAuth.new() to construct a GAuth instance. Provides methods for authorization,
    token issuance, validation, and audit logging.
    """

    def __init__(
        self,
        config: Config,
        token_store: Optional[TokenStore] = None,
        audit_logger: Optional[AuditLogger] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """
        Initialize GAuth instance.
        
        Args:
            config: GAuth configuration
            token_store: Token storage implementation (defaults to in-memory)
            audit_logger: Audit logging implementation (defaults to in-memory)
            rate_limiter: Rate limiting implementation (defaults to basic limiter)
        """
        self.config = config
        self.token_store = token_store or MemoryTokenStore()
        self.audit_logger = audit_logger or MemoryAuditLogger(max_entries=1000)
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter(
            max_requests=100,
            time_window=timedelta(minutes=1)
        )
        self.logger = logging.getLogger(__name__)

    @classmethod
    def new(
        cls,
        config: Config,
        audit_logger: Optional[AuditLogger] = None,
        token_store: Optional[TokenStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> "GAuth":
        """
        Create a new GAuth instance with the provided configuration and optional pluggable components.
        
        Args:
            config: GAuth configuration
            audit_logger: Optional audit logger (defaults to in-memory logger)
            token_store: Optional token store (defaults to in-memory store)
            rate_limiter: Optional rate limiter
            
        Returns:
            GAuth instance
            
        Raises:
            ValidationError: If configuration is invalid
            
        Example:
            gauth = GAuth.new(Config(
                auth_server_url="https://auth.example.com",
                client_id="my-client",
                client_secret="secret"
            ))
        """
        config.validate()
        return cls(config, token_store, audit_logger, rate_limiter)

    async def initiate_authorization(self, req: AuthorizationRequest) -> AuthorizationGrant:
        """
        Start the authorization process for a client.
        
        Args:
            req: Authorization request containing client_id and scopes
            
        Returns:
            AuthorizationGrant if successful
            
        Raises:
            AuthorizationError: If the request is invalid
            
        Example:
            grant = await gauth.initiate_authorization(
                AuthorizationRequest(client_id="my-client", scopes=["read"])
            )
        """
        try:
            self._validate_auth_request(req)
            
            grant_id = str(uuid.uuid4())
            grant = AuthorizationGrant(
                grant_id=grant_id,
                client_id=req.client_id,
                scope=req.scopes,
                valid_until=datetime.now() + self.config.access_token_expiry,
            )
            
            # Log audit event [GAuth]
            await self.audit_logger.log(AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type="auth_request",
                client_id=req.client_id,
                details={
                    "grant_id": grant.grant_id,
                    "scopes": req.scopes,
                    "action": "initiate",
                    "result": "granted"
                }
            ))
            
            return grant
            
        except Exception as e:
            self.logger.error(f"Authorization failed: {e}")
            raise AuthorizationError(f"Authorization failed: {e}")

    async def request_token(self, req: TokenRequest) -> TokenResponse:
        """
        Issue a new token based on an authorization grant.
        
        Args:
            req: Token request containing grant_id and scope
            
        Returns:
            TokenResponse if successful
            
        Raises:
            RateLimitError: If rate limit is exceeded
            TokenError: If token generation fails
            
        Example:
            response = await gauth.request_token(
                TokenRequest(grant_id=grant.grant_id, scope=["read"])
            )
        """
        try:
            # Check rate limit [GAuth]
            if not await self.rate_limiter.allow(req.grant_id):
                raise RateLimitError("Rate limit exceeded")
            
            # Generate token
            token = self._generate_token()
            expires_at = datetime.now() + self.config.access_token_expiry
            
            # Create access token data
            access_token = AccessToken(
                token=token,
                client_id=req.client_id or req.grant_id,
                scope=req.scope,
                expires_at=expires_at,
                restrictions=req.restrictions,
            )
            
            # Store token
            await self.token_store.store(token, access_token)
            
            # Log audit event [GAuth]
            await self.audit_logger.log(AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type="token_issued",
                client_id=access_token.client_id,
                details={
                    "grant_id": req.grant_id,
                    "scope": req.scope,
                    "expires_at": expires_at.isoformat(),
                }
            ))
            
            return TokenResponse(
                token=token,
                valid_until=expires_at,
                scope=req.scope,
                restrictions=req.restrictions,
            )
            
        except RateLimitError:
            raise
        except Exception as e:
            self.logger.error(f"Token request failed: {e}")
            raise TokenError(f"Token request failed: {e}")

    async def validate_token(self, token: str) -> AccessToken:
        """
        Check if a token is valid and return its associated data.
        
        Args:
            token: Token string to validate
            
        Returns:
            AccessToken if valid
            
        Raises:
            TokenError: If token is invalid or expired
            
        Example:
            access_token = await gauth.validate_token(token_string)
        """
        try:
            access_token = await self.token_store.get(token)
            if not access_token:
                raise TokenError("Token not found")
            
            if not access_token.is_valid:
                raise TokenError("Token is invalid or expired")
            
            return access_token
            
        except Exception as e:
            self.logger.error(f"Token validation failed: {e}")
            raise TokenError(f"Token validation failed: {e}")

    async def process_transaction(self, transaction: Transaction, token: str) -> TransactionResult:
        """
        Process a transaction with authorization validation.
        
        Args:
            transaction: Transaction to process
            token: Authorization token
            
        Returns:
            TransactionResult with success/failure information
            
        Raises:
            TransactionError: If transaction processing fails
            TokenError: If token is invalid
            
        Example:
            result = await gauth.process_transaction(
                Transaction(
                    transaction_id="tx-123",
                    client_id="my-client",
                    action="read_data",
                    resource="/api/data"
                ),
                token
            )
        """
        start_time = datetime.now()
        
        try:
            # Validate token
            access_token = await self.validate_token(token)
            
            # Check if client_id matches
            if access_token.client_id != transaction.client_id:
                raise TransactionError("Client ID mismatch")
            
            # Check scopes
            if not self._has_required_scopes(access_token.scope, transaction.scope_required):
                raise TransactionError("Insufficient scope")
            
            # Process the transaction (stub implementation)
            result_data = await self._execute_transaction(transaction)
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result = TransactionResult(
                transaction_id=transaction.transaction_id,
                success=True,
                result_data=result_data,
                execution_time_ms=execution_time,
            )
            
            # Log audit event [GAuth]
            await self.audit_logger.log(AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type="transaction",
                client_id=transaction.client_id,
                details={
                    "transaction_id": transaction.transaction_id,
                    "action": transaction.action,
                    "resource": transaction.resource,
                    "success": True,
                    "execution_time_ms": execution_time,
                }
            ))
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result = TransactionResult(
                transaction_id=transaction.transaction_id,
                success=False,
                error_message=str(e),
                execution_time_ms=execution_time,
            )
            
            # Log audit event [GAuth]
            await self.audit_logger.log(AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type="transaction",
                client_id=transaction.client_id,
                details={
                    "transaction_id": transaction.transaction_id,
                    "action": transaction.action,
                    "resource": transaction.resource,
                    "success": False,
                    "error": str(e),
                    "execution_time_ms": execution_time,
                }
            ))
            
            return result

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke an access token.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if token was revoked successfully
            
        Example:
            success = await gauth.revoke_token(token_string)
        """
        try:
            # Get token info before revoking for audit
            access_token = await self.token_store.get(token)
            
            # Remove token from store
            success = await self.token_store.delete(token)
            
            if success and access_token:
                # Log audit event [GAuth]
                await self.audit_logger.log(AuditEvent(
                    event_id=str(uuid.uuid4()),
                    event_type="token_revoked",
                    client_id=access_token.client_id,
                    details={
                        "token_id": token[:8] + "...",  # Partial token for security
                        "revoked_at": datetime.now().isoformat(),
                    }
                ))
            
            return success
            
        except Exception as e:
            self.logger.error(f"Token revocation failed: {e}")
            return False

    def get_audit_logger(self) -> AuditLogger:
        """
        Return the pluggable audit logger for inspection (RFC111: auditability).
        Use this to access or replace the audit logger for compliance and monitoring.
        """
        return self.audit_logger

    async def close(self) -> None:
        """
        Release any resources held by GAuth.
        For most in-memory/test use cases, this is a no-op.
        """
        if hasattr(self.token_store, 'close'):
            await self.token_store.close()
        if hasattr(self.audit_logger, 'close'):
            await self.audit_logger.close()

    def _validate_auth_request(self, req: AuthorizationRequest) -> None:
        """Validate authorization request"""
        if not req.client_id:
            raise ValidationError("client_id is required")
        if not req.scopes:
            raise ValidationError("scopes are required")

    def _generate_token(self) -> str:
        """Generate a new token (stub implementation)"""
        return str(uuid.uuid4())

    def _has_required_scopes(self, token_scopes: list, required_scopes: list) -> bool:
        """Check if token has all required scopes"""
        return all(scope in token_scopes for scope in required_scopes)

    async def _execute_transaction(self, transaction: Transaction) -> Dict[str, Any]:
        """
        Execute the actual transaction (stub implementation).
        In a real implementation, this would call the appropriate service.
        """
        # Stub implementation - in reality this would perform the actual action
        return {
            "action": transaction.action,
            "resource": transaction.resource,
            "parameters": transaction.parameters,
            "timestamp": datetime.now().isoformat(),
        }