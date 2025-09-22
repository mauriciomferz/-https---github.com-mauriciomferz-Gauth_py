"""
Authorization management for Power-of-Attorney (PoA) functionality.
Implements authorization scopes and management for RFC 115 compliance.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import logging

from .types import (
    PowerOfAttorney, Principal, Client, Authorization, AuthorizationType,
    GeographicRegion, IndustrySector, PoAStatus
)


logger = logging.getLogger(__name__)


class AuthorizationScope(Enum):
    """Scope of authorization for PoA operations."""
    TRANSACTION = "transaction"
    DECISION = "decision"
    ACTION = "action"
    SIGNATURE = "signature"
    DELEGATION = "delegation"


@dataclass
class TransactionAuthorization:
    """Authorization for transaction operations."""
    transaction_types: List[str] = field(default_factory=list)
    monetary_limits: Dict[str, float] = field(default_factory=dict)
    frequency_limits: Dict[str, int] = field(default_factory=dict)
    approval_required: bool = False
    notification_required: bool = True
    
    def is_authorized(self, transaction_type: str, amount: Optional[float] = None) -> bool:
        """Check if a transaction is authorized."""
        if transaction_type not in self.transaction_types:
            return False
        
        if amount is not None and transaction_type in self.monetary_limits:
            if amount > self.monetary_limits[transaction_type]:
                return False
        
        return True


@dataclass
class DecisionAuthorization:
    """Authorization for decision-making operations."""
    decision_types: List[str] = field(default_factory=list)
    decision_domains: List[str] = field(default_factory=list)
    requires_justification: bool = False
    review_required: bool = False
    
    def is_authorized(self, decision_type: str, domain: Optional[str] = None) -> bool:
        """Check if a decision is authorized."""
        if decision_type not in self.decision_types:
            return False
        
        if domain is not None and self.decision_domains:
            if domain not in self.decision_domains:
                return False
        
        return True


@dataclass
class ActionAuthorization:
    """Authorization for action operations."""
    action_types: List[str] = field(default_factory=list)
    physical_actions_allowed: bool = False
    digital_actions_allowed: bool = True
    restricted_actions: List[str] = field(default_factory=list)
    
    def is_authorized(self, action_type: str, is_physical: bool = False) -> bool:
        """Check if an action is authorized."""
        if action_type not in self.action_types:
            return False
        
        if action_type in self.restricted_actions:
            return False
        
        if is_physical and not self.physical_actions_allowed:
            return False
        
        if not is_physical and not self.digital_actions_allowed:
            return False
        
        return True


class AuthorizationManager:
    """
    Manages authorization for Power-of-Attorney operations.
    """
    
    def __init__(self):
        self._poa_registry: Dict[str, PowerOfAttorney] = {}
        self._authorization_cache: Dict[str, Dict[str, Any]] = {}

    async def register_poa(self, poa: PowerOfAttorney) -> None:
        """Register a Power-of-Attorney document."""
        if not poa.is_valid():
            raise ValueError(f"PoA {poa.id} is not valid")
        
        self._poa_registry[poa.id] = poa
        logger.info(f"Registered PoA {poa.id} for principal {poa.principal.id}")

    async def revoke_poa(self, poa_id: str, reason: str = "") -> bool:
        """Revoke a Power-of-Attorney document."""
        if poa_id not in self._poa_registry:
            return False
        
        poa = self._poa_registry[poa_id]
        poa.status = PoAStatus.REVOKED
        
        # Clear cache for this PoA
        if poa_id in self._authorization_cache:
            del self._authorization_cache[poa_id]
        
        logger.info(f"Revoked PoA {poa_id}: {reason}")
        return True

    async def check_transaction_authorization(
        self, 
        poa_id: str, 
        transaction_type: str,
        amount: Optional[float] = None,
        region: Optional[GeographicRegion] = None,
        sector: Optional[IndustrySector] = None
    ) -> bool:
        """Check if a transaction is authorized under the PoA."""
        poa = self._poa_registry.get(poa_id)
        if not poa or not poa.is_valid():
            return False
        
        # Check basic authorization
        if transaction_type not in poa.authorization.transaction_types:
            return False
        
        # Check geographic restrictions
        if region and poa.authorization.applicable_regions:
            if region not in poa.authorization.applicable_regions:
                return False
        
        # Check sector restrictions
        if sector and poa.authorization.applicable_sectors:
            if sector not in poa.authorization.applicable_sectors:
                return False
        
        # Check monetary limits from restrictions
        if amount is not None and poa.restrictions.monetary_limits:
            if transaction_type in poa.restrictions.monetary_limits:
                if amount > poa.restrictions.monetary_limits[transaction_type]:
                    return False
        
        return True

    async def check_decision_authorization(
        self,
        poa_id: str,
        decision_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if a decision is authorized under the PoA."""
        poa = self._poa_registry.get(poa_id)
        if not poa or not poa.is_valid():
            return False
        
        # Check if decision type is authorized
        if decision_type not in poa.authorization.decision_types:
            return False
        
        # Check if decision is in prohibited actions
        if decision_type in poa.restrictions.prohibited_actions:
            return False
        
        return True

    async def check_action_authorization(
        self,
        poa_id: str,
        action_type: str,
        is_physical: bool = False,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if an action is authorized under the PoA."""
        poa = self._poa_registry.get(poa_id)
        if not poa or not poa.is_valid():
            return False
        
        # Check if action type is authorized
        if action_type not in poa.authorization.action_types:
            return False
        
        # Check if action is prohibited
        if action_type in poa.restrictions.prohibited_actions:
            return False
        
        # For now, allow all actions that are explicitly authorized
        return True

    async def check_delegation_authorization(
        self,
        poa_id: str,
        sub_client_id: str,
        delegated_actions: List[str]
    ) -> bool:
        """Check if delegation is authorized under the PoA."""
        poa = self._poa_registry.get(poa_id)
        if not poa or not poa.is_valid():
            return False
        
        # Check if delegation is allowed
        if not poa.authorization.delegation_allowed:
            return False
        
        # Check sub-proxy rules if present
        if poa.authorization.sub_proxy_rules:
            rules = poa.authorization.sub_proxy_rules
            
            # Check if any delegated actions are prohibited
            for action in delegated_actions:
                if action in rules.prohibited_actions:
                    return False
        
        return True

    async def get_authorization_summary(self, poa_id: str) -> Dict[str, Any]:
        """Get a summary of what is authorized under the PoA."""
        poa = self._poa_registry.get(poa_id)
        if not poa:
            return {}
        
        return {
            'poa_id': poa_id,
            'status': poa.status.value,
            'is_valid': poa.is_valid(),
            'principal': poa.principal.name,
            'client': poa.client.name,
            'authorization_type': poa.authorization.type.value,
            'transaction_types': poa.authorization.transaction_types,
            'decision_types': poa.authorization.decision_types,
            'action_types': poa.authorization.action_types,
            'delegation_allowed': poa.authorization.delegation_allowed,
            'applicable_regions': [r.value for r in poa.authorization.applicable_regions],
            'applicable_sectors': [s.value for s in poa.authorization.applicable_sectors],
            'monetary_limits': poa.restrictions.monetary_limits,
            'prohibited_actions': poa.restrictions.prohibited_actions,
            'expires_at': poa.expiration_date.isoformat() if poa.expiration_date else None
        }

    async def list_active_poas(self, principal_id: Optional[str] = None, 
                              client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active PoAs, optionally filtered by principal or client."""
        active_poas = []
        
        for poa in self._poa_registry.values():
            if poa.status != PoAStatus.ACTIVE or not poa.is_valid():
                continue
            
            if principal_id and poa.principal.id != principal_id:
                continue
            
            if client_id and poa.client.id != client_id:
                continue
            
            active_poas.append(await self.get_authorization_summary(poa.id))
        
        return active_poas

    async def cleanup_expired_poas(self) -> int:
        """Remove expired PoAs from the registry."""
        expired_count = 0
        expired_poa_ids = []
        
        for poa_id, poa in self._poa_registry.items():
            if poa.is_expired():
                poa.status = PoAStatus.EXPIRED
                expired_poa_ids.append(poa_id)
                expired_count += 1
        
        # Clear cache for expired PoAs
        for poa_id in expired_poa_ids:
            if poa_id in self._authorization_cache:
                del self._authorization_cache[poa_id]
        
        logger.info(f"Marked {expired_count} PoAs as expired")
        return expired_count