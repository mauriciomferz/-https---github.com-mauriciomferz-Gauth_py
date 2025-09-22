"""
Authorization types for the GAuth protocol (GiFo-RfC 0111).
Implements authorization policies, subjects, resources, actions, and decisions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import json


class Effect(Enum):
    """Policy effect (RFC111: allow/deny decision)."""
    ALLOW = "allow"
    DENY = "deny"


# Constants for convenience
Allow = Effect.ALLOW
Deny = Effect.DENY


@dataclass
class Subject:
    """
    Entity requesting access (RFC111: power-of-attorney grantee, e.g. AI, user, or service).
    """
    id: str
    type: str
    roles: List[str] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)
    groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'type': self.type,
            'roles': self.roles,
            'attributes': self.attributes,
            'groups': self.groups
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Subject':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            type=data['type'],
            roles=data.get('roles', []),
            attributes=data.get('attributes', {}),
            groups=data.get('groups', [])
        )


@dataclass
class Resource:
    """
    Protected resource (RFC111: object of action/decision, e.g. data, service, asset).
    """
    id: str
    type: str
    owner: str
    attributes: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'type': self.type,
            'owner': self.owner,
            'attributes': self.attributes,
            'tags': self.tags
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Resource':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            type=data['type'],
            owner=data['owner'],
            attributes=data.get('attributes', {}),
            tags=data.get('tags', [])
        )


@dataclass
class Action:
    """
    Operation on a resource (RFC111: operation/transaction/decision to be authorized).
    """
    id: str
    type: str
    name: str
    attributes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'type': self.type,
            'name': self.name,
            'attributes': self.attributes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Action':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            type=data['type'],
            name=data['name'],
            attributes=data.get('attributes', {})
        )


class Condition(ABC):
    """
    Policy condition interface (RFC111: additional requirements for power-of-attorney, e.g. time, IP, role).
    """
    
    @abstractmethod
    async def evaluate(self, request: 'AccessRequest') -> bool:
        """
        Evaluate the condition against an access request.
        
        Args:
            request: The access request to evaluate
            
        Returns:
            bool: True if condition is satisfied, False otherwise
        """
        pass

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert condition to dictionary representation."""
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Condition':
        """Create condition from dictionary representation."""
        pass


@dataclass
class Policy:
    """
    Authorization policy (RFC111: formalizes power-of-attorney, scope, restrictions, and conditions).
    """
    id: str
    version: str
    name: str
    description: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Effect determines whether the policy allows or denies
    effect: Effect = Effect.ALLOW
    
    # Who this policy applies to
    subjects: List[Subject] = field(default_factory=list)
    
    # What resources this policy protects
    resources: List[Resource] = field(default_factory=list)
    
    # What actions are covered
    actions: List[Action] = field(default_factory=list)
    
    # Conditions that must be satisfied
    conditions: Dict[str, Condition] = field(default_factory=dict)
    
    # Priority determines policy evaluation order
    priority: int = 0
    
    # Status of the policy
    status: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'version': self.version,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'effect': self.effect.value,
            'subjects': [s.to_dict() for s in self.subjects],
            'resources': [r.to_dict() for r in self.resources],
            'actions': [a.to_dict() for a in self.actions],
            'conditions': {k: v.to_dict() for k, v in self.conditions.items()},
            'priority': self.priority,
            'status': self.status
        }

    async def matches(self, request: 'AccessRequest') -> bool:
        """
        Check if this policy matches the given request.
        
        Args:
            request: The access request to check
            
        Returns:
            bool: True if policy matches, False otherwise
        """
        # Check if any subject matches
        if self.subjects:
            subject_match = any(
                s.id == request.subject.id or
                s.type == request.subject.type or
                any(role in request.subject.roles for role in s.roles)
                for s in self.subjects
            )
            if not subject_match:
                return False
        
        # Check if any resource matches
        if self.resources:
            resource_match = any(
                r.id == request.resource.id or
                r.type == request.resource.type
                for r in self.resources
            )
            if not resource_match:
                return False
        
        # Check if any action matches
        if self.actions:
            action_match = any(
                a.id == request.action.id or
                a.type == request.action.type or
                a.name == request.action.name
                for a in self.actions
            )
            if not action_match:
                return False
        
        # Evaluate all conditions
        for condition in self.conditions.values():
            if not await condition.evaluate(request):
                return False
        
        return True


@dataclass
class AccessRequest:
    """
    Request to perform an action on a resource (RFC111: credentialized request, e.g. for transaction, decision, or action).
    """
    subject: Subject
    resource: Resource
    action: Action
    context: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'subject': self.subject.to_dict(),
            'resource': self.resource.to_dict(),
            'action': self.action.to_dict(),
            'context': self.context
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessRequest':
        """Create from dictionary representation."""
        return cls(
            subject=Subject.from_dict(data['subject']),
            resource=Resource.from_dict(data['resource']),
            action=Action.from_dict(data['action']),
            context=data.get('context', {})
        )


@dataclass
class AccessResponse:
    """
    Result of an access check (RFC111: result of PDP evaluation, with annotations for audit/compliance).
    """
    allowed: bool
    reason: str
    policy_id: Optional[str] = None
    annotations: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'allowed': self.allowed,
            'reason': self.reason,
            'policy_id': self.policy_id,
            'annotations': self.annotations
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessResponse':
        """Create from dictionary representation."""
        return cls(
            allowed=data['allowed'],
            reason=data['reason'],
            policy_id=data.get('policy_id'),
            annotations=data.get('annotations', {})
        )


@dataclass
class Decision:
    """
    Authorization decision (RFC111: PDP output, includes reason, policy, timestamp).
    """
    allowed: bool
    reason: str
    policy: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    annotations: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'allowed': self.allowed,
            'reason': self.reason,
            'policy': self.policy,
            'timestamp': self.timestamp.isoformat(),
            'annotations': self.annotations
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Decision':
        """Create from dictionary representation."""
        return cls(
            allowed=data['allowed'],
            reason=data['reason'],
            policy=data.get('policy'),
            timestamp=datetime.fromisoformat(data['timestamp']),
            annotations=data.get('annotations', {})
        )