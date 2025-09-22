"""
RFC 115 Power-of-Attorney GAuth Integration Module

This module provides integration between the PoA system and the GAuth protocol,
enabling PoA credentials to be embedded within GAuth tokens and validated during
authorization flows.

Copyright (c) 2025 Gimel Foundation and contributors. All rights reserved.
Licensed under Apache 2.0. See LICENSE for details.
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import uuid
import logging
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from .types import PoADefinition, PoAStatus
from .errors import PoAError, PoAValidationError
from ..token.types import TokenData, EnhancedToken
from ..types.common import AuditContext

logger = logging.getLogger(__name__)


@dataclass
class PoATokenExtension:
    """
    PoA token extension that embeds Power-of-Attorney capabilities
    into GAuth tokens as specified in RFC 115.
    """
    poa_definition_id: str
    poa_version: str
    principal_id: str
    authorized_client_id: str
    effective_scopes: List[str]
    effective_permissions: List[str]
    power_level_constraints: List['PowerLevelConstraint'] = field(default_factory=list)
    contextual_restrictions: List[str] = field(default_factory=list)
    valid_until: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=24))
    issued_at: datetime = field(default_factory=datetime.now)
    delegation_chain: List['DelegationLink'] = field(default_factory=list)


@dataclass
class PowerLevelConstraint:
    """Represents quantitative constraints on PoA authority."""
    constraint_type: str  # financial, transaction_count, etc.
    remaining_limit: Union[int, float, str]
    original_limit: Union[int, float, str]
    reset_period: Optional[str] = None  # daily, monthly, etc.
    last_reset: Optional[datetime] = None


@dataclass
class DelegationLink:
    """Represents one link in a delegation chain."""
    delegator_id: str
    delegate_id: str
    delegated_at: datetime
    delegated_scopes: List[str]
    delegation_level: int


class PoAStore(ABC):
    """Abstract interface for storing and retrieving PoA definitions."""
    
    @abstractmethod
    async def store_poa(self, poa: PoADefinition) -> bool:
        """Store a PoA definition."""
        pass
    
    @abstractmethod
    async def retrieve_poa(self, poa_id: str) -> Optional[PoADefinition]:
        """Retrieve a PoA definition by ID."""
        pass
    
    @abstractmethod
    async def update_poa(self, poa: PoADefinition) -> bool:
        """Update an existing PoA definition."""
        pass
    
    @abstractmethod
    async def delete_poa(self, poa_id: str) -> bool:
        """Delete a PoA definition."""
        pass
    
    @abstractmethod
    async def list_poas(self, principal_id: Optional[str] = None) -> List[PoADefinition]:
        """List PoA definitions, optionally filtered by principal."""
        pass


class PoAValidationRule(ABC):
    """Abstract base class for PoA validation rules."""
    
    @abstractmethod
    async def validate(self, poa: PoADefinition, context: Dict[str, Any]) -> bool:
        """Validate a PoA definition according to this rule."""
        pass


class PoAAuditLogger(ABC):
    """Abstract interface for PoA audit logging."""
    
    @abstractmethod
    async def log_poa_creation(self, poa: PoADefinition, actor: str) -> None:
        """Log creation of a new PoA definition."""
        pass
    
    @abstractmethod
    async def log_poa_activation(self, poa_id: str, actor: str) -> None:
        """Log activation of a PoA definition."""
        pass
    
    @abstractmethod
    async def log_poa_revocation(self, poa_id: str, reason: str, actor: str) -> None:
        """Log revocation of a PoA definition."""
        pass
    
    @abstractmethod
    async def log_poa_usage(self, poa_id: str, action: str, context: Dict[str, Any]) -> None:
        """Log usage of PoA authority."""
        pass
    
    @abstractmethod
    async def log_delegation(self, poa_id: str, delegator: str, delegate: str, scopes: List[str]) -> None:
        """Log delegation of PoA authority to sub-proxies."""
        pass
    
    @abstractmethod
    async def log_violation(self, poa_id: str, violation: str, context: Dict[str, Any]) -> None:
        """Log violations of PoA constraints or rules."""
        pass


class PoAGAuthIntegration:
    """
    Provides integration points between PoA and GAuth systems.
    Handles token creation, validation, and PoA lifecycle management.
    """
    
    def __init__(
        self,
        poa_store: PoAStore,
        validation_rules: Optional[List[PoAValidationRule]] = None,
        audit_logger: Optional[PoAAuditLogger] = None
    ):
        self.poa_store = poa_store
        self.validation_rules = validation_rules or []
        self.audit_logger = audit_logger
    
    async def create_poa_token(
        self,
        poa_definition_id: str,
        request_scopes: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> PoATokenExtension:
        """
        Create a new token with PoA extensions embedded.
        
        Args:
            poa_definition_id: ID of the PoA definition to use
            request_scopes: Requested scopes for the token
            context: Additional context for token creation
            
        Returns:
            PoATokenExtension with embedded PoA credentials
            
        Raises:
            PoAError: If PoA definition is invalid or not found
            PoAValidationError: If validation fails
        """
        context = context or {}
        
        # Retrieve PoA definition
        poa_definition = await self.poa_store.retrieve_poa(poa_definition_id)
        if not poa_definition:
            raise PoAError(f"PoA definition not found: {poa_definition_id}")
        
        # Validate PoA definition
        if not poa_definition.is_active():
            raise PoAError(f"PoA definition is not active: {poa_definition_id}")
        
        # Apply validation rules
        for rule in self.validation_rules:
            if not await rule.validate(poa_definition, context):
                raise PoAValidationError(f"PoA validation rule failed: {rule.__class__.__name__}")
        
        # Calculate effective scopes (intersection of requested and authorized)
        authorized_scopes = poa_definition.authorization.transaction_types
        effective_scopes = list(set(request_scopes) & set(authorized_scopes))
        
        # Create PoA token extension
        poa_extension = PoATokenExtension(
            poa_definition_id=poa_definition_id,
            poa_version=poa_definition.version,
            principal_id=poa_definition.principal.id,
            authorized_client_id=poa_definition.authorized_client.id,
            effective_scopes=effective_scopes,
            effective_permissions=self._calculate_effective_permissions(poa_definition, effective_scopes),
            power_level_constraints=self._extract_power_constraints(poa_definition),
            contextual_restrictions=poa_definition.authorization.restrictions or []
        )
        
        # Log PoA usage
        if self.audit_logger:
            await self.audit_logger.log_poa_usage(
                poa_definition_id,
                "token_creation",
                context
            )
        
        return poa_extension
    
    async def validate_poa_token(self, poa_extension: PoATokenExtension) -> bool:
        """
        Validate a token containing PoA extensions.
        
        Args:
            poa_extension: PoA token extension to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            # Check expiration
            if datetime.now() > poa_extension.valid_until:
                return False
            
            # Retrieve and validate PoA definition
            poa_definition = await self.poa_store.retrieve_poa(poa_extension.poa_definition_id)
            if not poa_definition or not poa_definition.is_active():
                return False
            
            # Validate version consistency
            if poa_definition.version != poa_extension.poa_version:
                return False
            
            # Validate scopes
            authorized_scopes = set(poa_definition.authorization.transaction_types)
            effective_scopes = set(poa_extension.effective_scopes)
            if not effective_scopes.issubset(authorized_scopes):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating PoA token: {e}")
            return False
    
    async def create_delegation(
        self,
        parent_poa_id: str,
        sub_client_id: str,
        delegated_scopes: List[str],
        delegator_id: str
    ) -> Optional[PoADefinition]:
        """
        Create a sub-proxy delegation as per RFC 115 requirements.
        
        Args:
            parent_poa_id: ID of the parent PoA definition
            sub_client_id: ID of the client receiving delegated authority
            delegated_scopes: Scopes being delegated
            delegator_id: ID of the entity performing the delegation
            
        Returns:
            New PoA definition for the sub-proxy, or None if delegation fails
        """
        # Retrieve parent PoA
        parent_poa = await self.poa_store.retrieve_poa(parent_poa_id)
        if not parent_poa:
            raise PoAError(f"Parent PoA not found: {parent_poa_id}")
        
        # Check if delegation is allowed
        if not parent_poa.authorization.delegation_allowed:
            raise PoAError("Delegation not allowed for this PoA")
        
        # Validate delegated scopes are subset of parent scopes
        parent_scopes = set(parent_poa.authorization.transaction_types)
        requested_scopes = set(delegated_scopes)
        if not requested_scopes.issubset(parent_scopes):
            raise PoAError("Delegated scopes exceed parent authorization")
        
        # Ensure GAuth compliance as required by RFC 115
        if not self._validate_gauth_compliance(sub_client_id):
            raise PoAError("Sub-proxy must comply with GAuth protocol per RFC 115")
        
        # Create delegation link
        delegation_link = DelegationLink(
            delegator_id=delegator_id,
            delegate_id=sub_client_id,
            delegated_at=datetime.now(),
            delegated_scopes=delegated_scopes,
            delegation_level=len(parent_poa.delegation_chain) + 1 if hasattr(parent_poa, 'delegation_chain') else 1
        )
        
        # Log delegation
        if self.audit_logger:
            await self.audit_logger.log_delegation(
                parent_poa_id,
                delegator_id,
                sub_client_id,
                delegated_scopes
            )
        
        # Note: In a full implementation, this would create a new PoA definition
        # for the sub-proxy with the appropriate delegation chain
        return None  # Placeholder
    
    def _calculate_effective_permissions(self, poa: PoADefinition, scopes: List[str]) -> List[str]:
        """Calculate effective permissions based on PoA definition and scopes."""
        permissions = []
        
        # Map scopes to permissions based on PoA authorization
        scope_permission_map = {
            'financial_transactions': ['read_financial_data', 'execute_payments'],
            'data_analysis': ['read_data', 'generate_reports'],
            'communication': ['send_emails', 'make_calls']
        }
        
        for scope in scopes:
            if scope in scope_permission_map:
                permissions.extend(scope_permission_map[scope])
        
        return list(set(permissions))
    
    def _extract_power_constraints(self, poa: PoADefinition) -> List[PowerLevelConstraint]:
        """Extract power level constraints from PoA requirements."""
        constraints = []
        
        if hasattr(poa, 'requirements') and hasattr(poa.requirements, 'power_limits'):
            power_limits = poa.requirements.power_limits
            
            if hasattr(power_limits, 'financial_limit') and power_limits.financial_limit:
                constraints.append(PowerLevelConstraint(
                    constraint_type='financial',
                    remaining_limit=power_limits.financial_limit,
                    original_limit=power_limits.financial_limit,
                    reset_period='daily'
                ))
        
        return constraints
    
    def _validate_gauth_compliance(self, client_id: str) -> bool:
        """Validate that a client complies with GAuth protocol requirements."""
        # Placeholder implementation
        # In practice, this would check client registration, capabilities, etc.
        return True


class MemoryPoAStore(PoAStore):
    """In-memory implementation of PoAStore for testing and development."""
    
    def __init__(self):
        self._store: Dict[str, PoADefinition] = {}
    
    async def store_poa(self, poa: PoADefinition) -> bool:
        """Store a PoA definition in memory."""
        self._store[poa.id] = poa
        return True
    
    async def retrieve_poa(self, poa_id: str) -> Optional[PoADefinition]:
        """Retrieve a PoA definition from memory."""
        return self._store.get(poa_id)
    
    async def update_poa(self, poa: PoADefinition) -> bool:
        """Update an existing PoA definition in memory."""
        if poa.id in self._store:
            self._store[poa.id] = poa
            return True
        return False
    
    async def delete_poa(self, poa_id: str) -> bool:
        """Delete a PoA definition from memory."""
        if poa_id in self._store:
            del self._store[poa_id]
            return True
        return False
    
    async def list_poas(self, principal_id: Optional[str] = None) -> List[PoADefinition]:
        """List PoA definitions, optionally filtered by principal."""
        poas = list(self._store.values())
        if principal_id:
            poas = [poa for poa in poas if poa.principal.id == principal_id]
        return poas


class ConsoleAuditLogger(PoAAuditLogger):
    """Console-based audit logger for development and testing."""
    
    async def log_poa_creation(self, poa: PoADefinition, actor: str) -> None:
        logger.info(f"PoA Created: {poa.id} by {actor}")
    
    async def log_poa_activation(self, poa_id: str, actor: str) -> None:
        logger.info(f"PoA Activated: {poa_id} by {actor}")
    
    async def log_poa_revocation(self, poa_id: str, reason: str, actor: str) -> None:
        logger.info(f"PoA Revoked: {poa_id} by {actor}, reason: {reason}")
    
    async def log_poa_usage(self, poa_id: str, action: str, context: Dict[str, Any]) -> None:
        logger.info(f"PoA Used: {poa_id}, action: {action}, context: {context}")
    
    async def log_delegation(self, poa_id: str, delegator: str, delegate: str, scopes: List[str]) -> None:
        logger.info(f"PoA Delegated: {poa_id}, {delegator} -> {delegate}, scopes: {scopes}")
    
    async def log_violation(self, poa_id: str, violation: str, context: Dict[str, Any]) -> None:
        logger.warning(f"PoA Violation: {poa_id}, violation: {violation}, context: {context}")