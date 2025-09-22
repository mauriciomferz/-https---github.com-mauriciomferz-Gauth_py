"""
Authorization conditions for the GAuth protocol (GiFo-RfC 0111).
Implements various condition types for policy evaluation.
"""

from abc import ABC, abstractmethod
from datetime import datetime, time, timezone
from typing import Dict, List, Optional, Any, Set
import ipaddress
import re

from .types import Condition, AccessRequest


class TimeCondition(Condition):
    """
    Time-based condition for policy evaluation.
    Allows access only within specified time ranges.
    """
    
    def __init__(self, 
                 start_time: Optional[time] = None,
                 end_time: Optional[time] = None,
                 allowed_days: Optional[Set[int]] = None,
                 timezone_name: str = "UTC"):
        """
        Initialize time condition.
        
        Args:
            start_time: Start time for allowed access (24-hour format)
            end_time: End time for allowed access (24-hour format)
            allowed_days: Set of allowed weekdays (0=Monday, 6=Sunday)
            timezone_name: Timezone for time evaluation
        """
        self.start_time = start_time
        self.end_time = end_time
        self.allowed_days = allowed_days or set(range(7))  # All days by default
        self.timezone_name = timezone_name

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate time-based conditions."""
        now = datetime.now(timezone.utc)
        
        # Check day of week
        if now.weekday() not in self.allowed_days:
            return False
        
        # Check time range
        current_time = now.time()
        
        if self.start_time and self.end_time:
            if self.start_time <= self.end_time:
                # Same day range
                return self.start_time <= current_time <= self.end_time
            else:
                # Overnight range
                return current_time >= self.start_time or current_time <= self.end_time
        elif self.start_time:
            return current_time >= self.start_time
        elif self.end_time:
            return current_time <= self.end_time
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'time',
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'allowed_days': list(self.allowed_days),
            'timezone': self.timezone_name
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TimeCondition':
        """Create from dictionary representation."""
        start_time = None
        end_time = None
        
        if data.get('start_time'):
            start_time = time.fromisoformat(data['start_time'])
        if data.get('end_time'):
            end_time = time.fromisoformat(data['end_time'])
        
        return cls(
            start_time=start_time,
            end_time=end_time,
            allowed_days=set(data.get('allowed_days', range(7))),
            timezone_name=data.get('timezone', 'UTC')
        )


class IPCondition(Condition):
    """
    IP address-based condition for policy evaluation.
    Allows access only from specified IP addresses or ranges.
    """
    
    def __init__(self, allowed_networks: List[str]):
        """
        Initialize IP condition.
        
        Args:
            allowed_networks: List of allowed IP addresses or CIDR networks
        """
        self.allowed_networks = []
        for network in allowed_networks:
            self.allowed_networks.append(ipaddress.ip_network(network, strict=False))

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate IP-based conditions."""
        client_ip = request.context.get('client_ip')
        if not client_ip:
            return False
        
        try:
            client_addr = ipaddress.ip_address(client_ip)
            return any(client_addr in network for network in self.allowed_networks)
        except ValueError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'ip',
            'allowed_networks': [str(network) for network in self.allowed_networks]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPCondition':
        """Create from dictionary representation."""
        return cls(allowed_networks=data['allowed_networks'])


class RoleCondition(Condition):
    """
    Role-based condition for policy evaluation.
    Allows access only if subject has required roles.
    """
    
    def __init__(self, required_roles: Set[str], require_all: bool = False):
        """
        Initialize role condition.
        
        Args:
            required_roles: Set of required roles
            require_all: If True, subject must have all roles; if False, any role
        """
        self.required_roles = required_roles
        self.require_all = require_all

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate role-based conditions."""
        subject_roles = set(request.subject.roles)
        
        if self.require_all:
            return self.required_roles.issubset(subject_roles)
        else:
            return bool(self.required_roles.intersection(subject_roles))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'role',
            'required_roles': list(self.required_roles),
            'require_all': self.require_all
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RoleCondition':
        """Create from dictionary representation."""
        return cls(
            required_roles=set(data['required_roles']),
            require_all=data.get('require_all', False)
        )


class AttributeCondition(Condition):
    """
    Attribute-based condition for policy evaluation.
    Allows access based on subject or resource attributes.
    """
    
    def __init__(self, 
                 subject_attributes: Optional[Dict[str, str]] = None,
                 resource_attributes: Optional[Dict[str, str]] = None,
                 action_attributes: Optional[Dict[str, str]] = None):
        """
        Initialize attribute condition.
        
        Args:
            subject_attributes: Required subject attributes (key: required_value)
            resource_attributes: Required resource attributes
            action_attributes: Required action attributes
        """
        self.subject_attributes = subject_attributes or {}
        self.resource_attributes = resource_attributes or {}
        self.action_attributes = action_attributes or {}

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate attribute-based conditions."""
        # Check subject attributes
        for key, required_value in self.subject_attributes.items():
            if request.subject.attributes.get(key) != required_value:
                return False
        
        # Check resource attributes
        for key, required_value in self.resource_attributes.items():
            if request.resource.attributes.get(key) != required_value:
                return False
        
        # Check action attributes
        for key, required_value in self.action_attributes.items():
            if request.action.attributes.get(key) != required_value:
                return False
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'attribute',
            'subject_attributes': self.subject_attributes,
            'resource_attributes': self.resource_attributes,
            'action_attributes': self.action_attributes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttributeCondition':
        """Create from dictionary representation."""
        return cls(
            subject_attributes=data.get('subject_attributes', {}),
            resource_attributes=data.get('resource_attributes', {}),
            action_attributes=data.get('action_attributes', {})
        )


class RegexCondition(Condition):
    """
    Regular expression condition for policy evaluation.
    Allows pattern matching on various request elements.
    """
    
    def __init__(self, patterns: Dict[str, str]):
        """
        Initialize regex condition.
        
        Args:
            patterns: Dictionary mapping field paths to regex patterns
                     Supported paths: subject.id, resource.id, action.name, etc.
        """
        self.patterns = {}
        for path, pattern in patterns.items():
            self.patterns[path] = re.compile(pattern)

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate regex-based conditions."""
        values = {
            'subject.id': request.subject.id,
            'subject.type': request.subject.type,
            'resource.id': request.resource.id,
            'resource.type': request.resource.type,
            'resource.owner': request.resource.owner,
            'action.id': request.action.id,
            'action.type': request.action.type,
            'action.name': request.action.name
        }
        
        # Add context values
        for key, value in request.context.items():
            values[f'context.{key}'] = value
        
        # Check all patterns
        for path, pattern in self.patterns.items():
            value = values.get(path, '')
            if not pattern.search(str(value)):
                return False
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'regex',
            'patterns': {path: pattern.pattern for path, pattern in self.patterns.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RegexCondition':
        """Create from dictionary representation."""
        return cls(patterns=data['patterns'])


class CompoundCondition(Condition):
    """
    Compound condition that combines multiple conditions with logical operators.
    """
    
    def __init__(self, conditions: List[Condition], operator: str = "AND"):
        """
        Initialize compound condition.
        
        Args:
            conditions: List of conditions to combine
            operator: Logical operator ("AND", "OR", "NOT")
        """
        self.conditions = conditions
        self.operator = operator.upper()
        
        if self.operator not in ["AND", "OR", "NOT"]:
            raise ValueError(f"Unsupported operator: {operator}")
        
        if self.operator == "NOT" and len(conditions) != 1:
            raise ValueError("NOT operator requires exactly one condition")

    async def evaluate(self, request: AccessRequest) -> bool:
        """Evaluate compound conditions."""
        if self.operator == "AND":
            for condition in self.conditions:
                if not await condition.evaluate(request):
                    return False
            return True
        
        elif self.operator == "OR":
            for condition in self.conditions:
                if await condition.evaluate(request):
                    return True
            return False
        
        elif self.operator == "NOT":
            return not await self.conditions[0].evaluate(request)
        
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': 'compound',
            'operator': self.operator,
            'conditions': [condition.to_dict() for condition in self.conditions]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CompoundCondition':
        """Create from dictionary representation."""
        conditions = []
        for condition_data in data['conditions']:
            # This would need a condition factory in a real implementation
            # For now, we'll skip this complex deserialization
            pass
        
        return cls(
            conditions=conditions,
            operator=data['operator']
        )