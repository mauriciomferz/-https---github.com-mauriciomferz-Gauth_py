"""
Authorization context management for the GAuth protocol (GiFo-RfC 0111).
Provides context and metadata for authorization decisions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextvars import ContextVar
import asyncio


# Context variables for request-scoped data
_authorization_context: ContextVar[Optional['AuthorizationContext']] = ContextVar(
    'authorization_context', default=None
)


@dataclass
class RequestContext:
    """
    Context information for an authorization request.
    """
    request_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'client_ip': self.client_ip,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'correlation_id': self.correlation_id,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RequestContext':
        """Create from dictionary representation."""
        return cls(
            request_id=data['request_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            client_ip=data.get('client_ip'),
            user_agent=data.get('user_agent'),
            session_id=data.get('session_id'),
            correlation_id=data.get('correlation_id'),
            metadata=data.get('metadata', {})
        )


@dataclass
class AuthorizationContext:
    """
    Authorization context that tracks the current authorization state.
    """
    request_context: RequestContext
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    policies_evaluated: List[str] = field(default_factory=list)
    conditions_evaluated: List[str] = field(default_factory=list)
    evaluation_time: Optional[float] = None
    cache_hits: int = 0
    cache_misses: int = 0

    def add_decision(self, decision: Dict[str, Any]) -> None:
        """Add a decision to the context."""
        self.decisions.append({
            **decision,
            'timestamp': datetime.now().isoformat()
        })

    def add_policy_evaluated(self, policy_id: str) -> None:
        """Record that a policy was evaluated."""
        self.policies_evaluated.append(policy_id)

    def add_condition_evaluated(self, condition_name: str) -> None:
        """Record that a condition was evaluated."""
        self.conditions_evaluated.append(condition_name)

    def record_cache_hit(self) -> None:
        """Record a cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss."""
        self.cache_misses += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'request_context': self.request_context.to_dict(),
            'decisions': self.decisions,
            'policies_evaluated': self.policies_evaluated,
            'conditions_evaluated': self.conditions_evaluated,
            'evaluation_time': self.evaluation_time,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses
        }


def get_authorization_context() -> Optional[AuthorizationContext]:
    """Get the current authorization context."""
    return _authorization_context.get()


def set_authorization_context(context: AuthorizationContext) -> None:
    """Set the current authorization context."""
    _authorization_context.set(context)


def clear_authorization_context() -> None:
    """Clear the current authorization context."""
    _authorization_context.set(None)


class AuthorizationContextManager:
    """
    Context manager for authorization context.
    """
    
    def __init__(self, context: AuthorizationContext):
        self.context = context
        self.previous_context: Optional[AuthorizationContext] = None

    async def __aenter__(self) -> AuthorizationContext:
        """Enter the context."""
        self.previous_context = get_authorization_context()
        set_authorization_context(self.context)
        return self.context

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the context."""
        set_authorization_context(self.previous_context)


def create_authorization_context(request_id: str, **kwargs) -> AuthorizationContext:
    """
    Create a new authorization context.
    
    Args:
        request_id: Unique identifier for the request
        **kwargs: Additional context parameters
        
    Returns:
        AuthorizationContext: New context instance
    """
    request_context = RequestContext(
        request_id=request_id,
        client_ip=kwargs.get('client_ip'),
        user_agent=kwargs.get('user_agent'),
        session_id=kwargs.get('session_id'),
        correlation_id=kwargs.get('correlation_id'),
        metadata=kwargs.get('metadata', {})
    )
    
    return AuthorizationContext(request_context=request_context)


async def with_authorization_context(
    request_id: str, 
    func, 
    *args, 
    **kwargs
) -> Any:
    """
    Execute a function within an authorization context.
    
    Args:
        request_id: Unique identifier for the request
        func: Function to execute
        *args: Arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Any: Result of the function execution
    """
    context = create_authorization_context(request_id)
    
    async with AuthorizationContextManager(context):
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)