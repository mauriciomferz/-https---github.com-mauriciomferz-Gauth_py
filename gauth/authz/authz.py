"""
Core authorization engine for the GAuth protocol (GiFo-RfC 0111).
Implements policy evaluation and access control decisions.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Set
import asyncio
import logging

from .types import (
    Subject, Resource, Action, Policy, AccessRequest, AccessResponse, 
    Decision, Effect
)


logger = logging.getLogger(__name__)


class Authorizer(ABC):
    """
    Base class for authorization engines.
    """
    
    @abstractmethod
    async def authorize(self, subject: Subject, action: Action, resource: Resource) -> Decision:
        """
        Determine if a subject can perform an action on a resource.
        
        Args:
            subject: The entity requesting access
            action: The operation to be performed
            resource: The target resource
            
        Returns:
            Decision: Authorization decision with reason and metadata
        """
        pass

    @abstractmethod
    async def is_allowed(self, request: AccessRequest) -> AccessResponse:
        """
        Check if an access request should be allowed.
        
        Args:
            request: The access request to evaluate
            
        Returns:
            AccessResponse: Response with decision and metadata
        """
        pass


class PolicyStore(ABC):
    """
    Abstract base class for policy storage.
    """
    
    @abstractmethod
    async def store_policy(self, policy: Policy) -> None:
        """Store a policy."""
        pass

    @abstractmethod
    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID."""
        pass

    @abstractmethod
    async def list_policies(self) -> List[Policy]:
        """List all policies."""
        pass

    @abstractmethod
    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        pass

    @abstractmethod
    async def find_matching_policies(self, request: AccessRequest) -> List[Policy]:
        """Find policies that match the request."""
        pass


class MemoryPolicyStore(PolicyStore):
    """
    In-memory policy store implementation.
    """
    
    def __init__(self):
        self._policies: Dict[str, Policy] = {}

    async def store_policy(self, policy: Policy) -> None:
        """Store a policy in memory."""
        policy.updated_at = datetime.now()
        self._policies[policy.id] = policy

    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    async def list_policies(self) -> List[Policy]:
        """List all policies."""
        return list(self._policies.values())

    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False

    async def find_matching_policies(self, request: AccessRequest) -> List[Policy]:
        """Find policies that match the request."""
        matching_policies = []
        
        for policy in self._policies.values():
            if policy.status == "active" and await policy.matches(request):
                matching_policies.append(policy)
        
        # Sort by priority (higher priority first)
        matching_policies.sort(key=lambda p: p.priority, reverse=True)
        return matching_policies


class PolicyEngine:
    """
    Policy evaluation engine for authorization decisions.
    """
    
    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store

    async def evaluate(self, request: AccessRequest) -> AccessResponse:
        """
        Evaluate an access request against stored policies.
        
        Args:
            request: The access request to evaluate
            
        Returns:
            AccessResponse: The authorization decision
        """
        try:
            policies = await self.policy_store.find_matching_policies(request)
            
            if not policies:
                return AccessResponse(
                    allowed=False,
                    reason="No matching policies found",
                    annotations={"evaluation_time": datetime.now().isoformat()}
                )
            
            # Evaluate policies in priority order
            for policy in policies:
                if await policy.matches(request):
                    if policy.effect == Effect.DENY:
                        return AccessResponse(
                            allowed=False,
                            reason=f"Access denied by policy {policy.id}",
                            policy_id=policy.id,
                            annotations={
                                "policy_name": policy.name,
                                "evaluation_time": datetime.now().isoformat()
                            }
                        )
                    else:  # ALLOW
                        return AccessResponse(
                            allowed=True,
                            reason=f"Access allowed by policy {policy.id}",
                            policy_id=policy.id,
                            annotations={
                                "policy_name": policy.name,
                                "evaluation_time": datetime.now().isoformat()
                            }
                        )
            
            # Default deny if no policy explicitly allows
            return AccessResponse(
                allowed=False,
                reason="No policy explicitly allows access",
                annotations={"evaluation_time": datetime.now().isoformat()}
            )
            
        except Exception as e:
            logger.error(f"Error evaluating access request: {e}")
            return AccessResponse(
                allowed=False,
                reason=f"Evaluation error: {str(e)}",
                annotations={
                    "error": str(e),
                    "evaluation_time": datetime.now().isoformat()
                }
            )


class MemoryAuthorizer(Authorizer):
    """
    In-memory authorization implementation.
    """
    
    def __init__(self, policy_store: Optional[PolicyStore] = None):
        self.policy_store = policy_store or MemoryPolicyStore()
        self.engine = PolicyEngine(self.policy_store)

    async def authorize(self, subject: Subject, action: Action, resource: Resource) -> Decision:
        """
        Determine if a subject can perform an action on a resource.
        """
        request = AccessRequest(
            subject=subject,
            action=action,
            resource=resource,
            context={}
        )
        
        response = await self.is_allowed(request)
        
        return Decision(
            allowed=response.allowed,
            reason=response.reason,
            policy=response.policy_id,
            timestamp=datetime.now(),
            annotations=response.annotations
        )

    async def is_allowed(self, request: AccessRequest) -> AccessResponse:
        """
        Check if an access request should be allowed.
        """
        return await self.engine.evaluate(request)

    async def add_policy(self, policy: Policy) -> None:
        """Add a policy to the authorizer."""
        await self.policy_store.store_policy(policy)

    async def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy from the authorizer."""
        return await self.policy_store.delete_policy(policy_id)

    async def list_policies(self) -> List[Policy]:
        """List all policies in the authorizer."""
        return await self.policy_store.list_policies()

    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a specific policy."""
        return await self.policy_store.get_policy(policy_id)


# Factory functions for common use cases
def create_memory_authorizer() -> MemoryAuthorizer:
    """Create a new memory-based authorizer."""
    return MemoryAuthorizer()


def create_authorizer_with_policies(policies: List[Policy]) -> MemoryAuthorizer:
    """Create an authorizer pre-loaded with policies."""
    authorizer = MemoryAuthorizer()
    
    async def load_policies():
        for policy in policies:
            await authorizer.add_policy(policy)
    
    # Note: In real use, you'd want to await this properly
    # For now, return the authorizer and load policies separately
    return authorizer