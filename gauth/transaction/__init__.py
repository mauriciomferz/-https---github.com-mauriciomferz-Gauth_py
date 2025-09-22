"""
Transaction processing for GAuth protocol.

This module provides transaction validation, processing, and monitoring
capabilities as required by RFC111 for complete authorization flows.
"""

import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from ..core.types import Transaction, TransactionResult
from ..errors import ErrorCode, TransactionError, ValidationError


class TransactionStatus(Enum):
    """Transaction processing status."""
    
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class TransactionType(Enum):
    """Types of transactions that can be processed."""
    
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    DELETE_DATA = "delete_data"
    EXECUTE_COMMAND = "execute_command"
    PROCESS_PAYMENT = "process_payment"
    CREATE_RESOURCE = "create_resource"
    UPDATE_RESOURCE = "update_resource"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"


@dataclass
class TransactionDetails:
    """
    Detailed transaction information with validation and metadata.
    
    Attributes:
        transaction_id: Unique identifier for the transaction
        transaction_type: Type of transaction being performed
        resource: Resource being accessed or modified
        action: Specific action being performed
        parameters: Transaction-specific parameters
        metadata: Additional transaction metadata
        monetary_amount: Amount if this is a monetary transaction
        currency: Currency code for monetary transactions
        restrictions: Any restrictions on the transaction
        timeout: Transaction timeout
        created_at: When transaction was created
        expires_at: When transaction expires
    """
    
    transaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transaction_type: TransactionType = TransactionType.READ_DATA
    resource: str = ""
    action: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    monetary_amount: Optional[float] = None
    currency: Optional[str] = None
    restrictions: List[str] = field(default_factory=list)
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = self.created_at + self.timeout
    
    def validate(self) -> None:
        """Validate transaction details."""
        errors = []
        
        if not self.transaction_id:
            errors.append("Transaction ID is required")
        
        if not self.resource:
            errors.append("Resource is required")
        
        if not self.action:
            errors.append("Action is required")
        
        if self.monetary_amount is not None:
            if self.monetary_amount < 0:
                errors.append("Monetary amount cannot be negative")
            if not self.currency:
                errors.append("Currency is required for monetary transactions")
        
        if self.expires_at and self.expires_at <= datetime.now():
            errors.append("Transaction has expired")
        
        if errors:
            raise ValidationError(
                code=ErrorCode.VALIDATION_FAILED,
                message=f"Transaction validation failed: {'; '.join(errors)}"
            )
    
    def is_monetary(self) -> bool:
        """Check if this is a monetary transaction."""
        return self.monetary_amount is not None and self.monetary_amount > 0
    
    def requires_authorization(self) -> bool:
        """Check if transaction requires authorization."""
        return (
            self.transaction_type in [
                TransactionType.WRITE_DATA,
                TransactionType.DELETE_DATA,
                TransactionType.EXECUTE_COMMAND,
                TransactionType.PROCESS_PAYMENT,
                TransactionType.CREATE_RESOURCE,
                TransactionType.UPDATE_RESOURCE,
            ]
            or self.is_monetary()
            or "admin" in self.restrictions
        )
    
    def get_metadata(self) -> Dict[str, str]:
        """Get metadata as string dictionary for compatibility."""
        return {k: str(v) for k, v in self.metadata.items()}
    
    def is_expired(self) -> bool:
        """Check if transaction has expired."""
        return self.expires_at and datetime.now() > self.expires_at
    
    def get_required_scopes(self) -> List[str]:
        """Get required scopes for this transaction."""
        scope_map = {
            TransactionType.READ_DATA: ["read"],
            TransactionType.WRITE_DATA: ["write"],
            TransactionType.DELETE_DATA: ["delete", "write"],
            TransactionType.EXECUTE_COMMAND: ["execute"],
            TransactionType.PROCESS_PAYMENT: ["payment:execute"],
            TransactionType.CREATE_RESOURCE: ["create", "write"],
            TransactionType.UPDATE_RESOURCE: ["update", "write"],
            TransactionType.AUTHENTICATE: ["auth"],
            TransactionType.AUTHORIZE: ["auth", "admin"],
        }
        
        scopes = scope_map.get(self.transaction_type, ["read"])
        
        # Add specific scopes based on restrictions
        if "admin" in self.restrictions:
            scopes.append("admin")
        if self.is_monetary():
            scopes.append("payment:execute")
        
        return list(set(scopes))  # Remove duplicates


@dataclass
class TransactionContext:
    """Context information for transaction processing."""
    
    client_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    additional_context: Dict[str, Any] = field(default_factory=dict)


class TransactionProcessor:
    """
    Process transactions with proper authorization and validation.
    
    Handles the complete transaction lifecycle including validation,
    authorization checking, processing, and result tracking.
    """
    
    def __init__(self, gauth_instance):
        self.gauth = gauth_instance
        self._active_transactions: Dict[str, TransactionDetails] = {}
        self._transaction_results: Dict[str, TransactionResult] = {}
    
    async def process_transaction(
        self,
        transaction: Transaction,
        context: TransactionContext,
        token: Optional[str] = None
    ) -> TransactionResult:
        """
        Process a transaction with full validation and authorization.
        
        Args:
            transaction: Transaction to process
            context: Transaction context
            token: Access token for authorization
            
        Returns:
            TransactionResult with success/failure information
        """
        start_time = datetime.now()
        transaction_id = transaction.transaction_id
        
        try:
            # Convert to detailed transaction
            details = self._convert_to_details(transaction)
            
            # Validate transaction
            details.validate()
            
            # Check expiration
            if details.is_expired():
                raise TransactionError(
                    code=ErrorCode.TRANSACTION_TIMEOUT,
                    message="Transaction has expired",
                    transaction_id=transaction_id
                )
            
            # Store as active transaction
            self._active_transactions[transaction_id] = details
            
            # Authorize transaction if token provided
            if token:
                await self._authorize_transaction(details, token, context)
            
            # Process the transaction
            result = await self._execute_transaction(details, context)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create result
            transaction_result = TransactionResult(
                transaction_id=transaction_id,
                success=result.get("success", True),
                result=result.get("result", "completed"),
                error_message=result.get("error"),
                execution_time_ms=execution_time,
                timestamp=datetime.now(),
                metadata=result.get("metadata", {})
            )
            
            # Store result
            self._transaction_results[transaction_id] = transaction_result
            
            return transaction_result
        
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create failure result
            error_message = str(e)
            if isinstance(e, TransactionError):
                error_message = e.message
            
            transaction_result = TransactionResult(
                transaction_id=transaction_id,
                success=False,
                result="failed",
                error_message=error_message,
                execution_time_ms=execution_time,
                timestamp=datetime.now(),
                metadata={"error_type": type(e).__name__}
            )
            
            self._transaction_results[transaction_id] = transaction_result
            
            # Re-raise for caller handling
            raise
        
        finally:
            # Remove from active transactions
            self._active_transactions.pop(transaction_id, None)
    
    def _convert_to_details(self, transaction: Transaction) -> TransactionDetails:
        """Convert Transaction to TransactionDetails."""
        # Parse action to determine transaction type
        action_type_map = {
            "read": TransactionType.READ_DATA,
            "write": TransactionType.WRITE_DATA,
            "delete": TransactionType.DELETE_DATA,
            "execute": TransactionType.EXECUTE_COMMAND,
            "payment": TransactionType.PROCESS_PAYMENT,
            "create": TransactionType.CREATE_RESOURCE,
            "update": TransactionType.UPDATE_RESOURCE,
        }
        
        transaction_type = TransactionType.READ_DATA
        for key, ttype in action_type_map.items():
            if key in transaction.action.lower():
                transaction_type = ttype
                break
        
        return TransactionDetails(
            transaction_id=transaction.transaction_id,
            transaction_type=transaction_type,
            resource=transaction.resource,
            action=transaction.action,
            parameters=transaction.parameters or {},
            metadata=transaction.metadata or {},
        )
    
    async def _authorize_transaction(
        self,
        details: TransactionDetails,
        token: str,
        context: TransactionContext
    ) -> None:
        """Authorize transaction using provided token."""
        # Validate token
        token_data = await self.gauth.validate_token(token)
        if not token_data:
            raise TransactionError(
                code=ErrorCode.INVALID_TOKEN,
                message="Invalid or expired token",
                transaction_id=details.transaction_id
            )
        
        # Check scopes
        required_scopes = details.get_required_scopes()
        token_scopes = token_data.scope if isinstance(token_data.scope, list) else [token_data.scope]
        
        missing_scopes = set(required_scopes) - set(token_scopes)
        if missing_scopes:
            raise TransactionError(
                code=ErrorCode.INSUFFICIENT_SCOPE,
                message=f"Insufficient scope. Required: {required_scopes}, Missing: {list(missing_scopes)}",
                transaction_id=details.transaction_id
            )
        
        # Verify client matches
        if context.client_id != token_data.client_id:
            raise TransactionError(
                code=ErrorCode.UNAUTHORIZED_CLIENT,
                message="Token client does not match transaction client",
                transaction_id=details.transaction_id
            )
    
    async def _execute_transaction(
        self,
        details: TransactionDetails,
        context: TransactionContext
    ) -> Dict[str, Any]:
        """Execute the actual transaction logic."""
        # This is a mock implementation - in real scenarios,
        # this would interact with actual business logic
        
        if details.transaction_type == TransactionType.READ_DATA:
            return {
                "success": True,
                "result": f"Read data from {details.resource}",
                "metadata": {"bytes_read": 1024}
            }
        
        elif details.transaction_type == TransactionType.WRITE_DATA:
            return {
                "success": True,
                "result": f"Wrote data to {details.resource}",
                "metadata": {"bytes_written": 512}
            }
        
        elif details.transaction_type == TransactionType.PROCESS_PAYMENT:
            if details.monetary_amount and details.monetary_amount > 10000:
                return {
                    "success": False,
                    "error": "Payment amount exceeds limit",
                    "result": "rejected"
                }
            return {
                "success": True,
                "result": f"Payment processed: {details.monetary_amount} {details.currency}",
                "metadata": {"payment_id": str(uuid.uuid4())}
            }
        
        else:
            return {
                "success": True,
                "result": f"Executed {details.action} on {details.resource}",
                "metadata": {"operation": details.transaction_type.value}
            }
    
    def get_transaction_result(self, transaction_id: str) -> Optional[TransactionResult]:
        """Get result of a processed transaction."""
        return self._transaction_results.get(transaction_id)
    
    def get_active_transactions(self) -> List[TransactionDetails]:
        """Get list of currently active transactions."""
        return list(self._active_transactions.values())
    
    def cancel_transaction(self, transaction_id: str) -> bool:
        """Cancel an active transaction."""
        if transaction_id in self._active_transactions:
            del self._active_transactions[transaction_id]
            
            # Create cancellation result
            self._transaction_results[transaction_id] = TransactionResult(
                transaction_id=transaction_id,
                success=False,
                result="cancelled",
                error_message="Transaction was cancelled",
                execution_time_ms=0,
                timestamp=datetime.now()
            )
            return True
        return False
    
    def cleanup_expired_transactions(self) -> int:
        """Remove expired transactions and return count removed."""
        now = datetime.now()
        expired_ids = [
            tid for tid, details in self._active_transactions.items()
            if details.is_expired()
        ]
        
        for tid in expired_ids:
            del self._active_transactions[tid]
            self._transaction_results[tid] = TransactionResult(
                transaction_id=tid,
                success=False,
                result="expired",
                error_message="Transaction expired",
                execution_time_ms=0,
                timestamp=now
            )
        
        return len(expired_ids)