"""
Event management and publishing capabilities for GAuth protocol.

RFC 0111 (GAuth) Compliance Notice:
  - This file is part of a GAuth implementation and must comply with GiFo-RfC 0111 (September 2025).
  - License: Apache 2.0 (OAuth, OpenID Connect), MIT (MCP), Gimel Foundation legal provisions apply.
  - Exclusion Enforcement: This implementation does NOT use Web3/blockchain, DNA/genetic identity, or AI lifecycle control as per RFC 0111 exclusions.
  - For full legal and compliance details, see the LICENSE file and RFC 0111 documentation.
  - No decentralized authorization or excluded technologies are present in this file.

This file implements the unified, type-safe event system as required by RFC111:
  - Typed event handling for authentication, authorization, token, and system events
  - All event types are enums/constants (no stringly-typed events)
  - Supports audit, compliance, and activity tracking for all protocol steps
"""

import asyncio
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field


class EventType(Enum):
    """Typed event types for GAuth protocol compliance."""
    
    # Service lifecycle events
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SERVICE_ERROR = "service_error"
    
    # Authentication events
    AUTH_REQUEST = "auth_request"
    AUTH_GRANT = "auth_grant"
    AUTH_DENIED = "auth_denied"
    
    # Authorization events
    AUTHZ_REQUEST = "authz_request"
    AUTHZ_GRANTED = "authz_granted"
    AUTHZ_DENIED = "authz_denied"
    
    # Token events
    TOKEN_ISSUED = "token_issued"
    TOKEN_VALIDATED = "token_validated"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    
    # Transaction events
    TRANSACTION_START = "transaction_start"
    TRANSACTION_SUCCESS = "transaction_success"
    TRANSACTION_FAILURE = "transaction_failure"
    
    # System events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    AUDIT_LOG_CREATED = "audit_log_created"
    ERROR_OCCURRED = "error_occurred"


class EventAction(Enum):
    """Actions that can be performed within events."""
    
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    VALIDATE = "validate"
    GRANT = "grant"
    DENY = "deny"
    REVOKE = "revoke"
    EXPIRE = "expire"
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS = "access"
    PROCESS = "process"


@dataclass
class Event:
    """
    Unified event structure for GAuth protocol.
    
    Attributes:
        id: Unique event identifier
        type: Event type from EventType enum
        action: Action being performed
        subject: Entity performing the action (user, client, service)
        resource: Resource being acted upon
        timestamp: When the event occurred
        metadata: Additional event-specific data
        source: Source system/component that generated the event
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType = EventType.SERVICE_STARTED
    action: EventAction = EventAction.CREATE
    subject: str = ""
    resource: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "gauth"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type.value,
            "action": self.action.value,
            "subject": self.subject,
            "resource": self.resource,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "source": self.source,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create event from dictionary representation."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            type=EventType(data.get("type", EventType.SERVICE_STARTED.value)),
            action=EventAction(data.get("action", EventAction.CREATE.value)),
            subject=data.get("subject", ""),
            resource=data.get("resource", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat())),
            metadata=data.get("metadata", {}),
            source=data.get("source", "gauth"),
        )


class EventHandler:
    """Base class for event handlers."""
    
    async def handle(self, event: Event) -> None:
        """Handle an event. Override in subclasses."""
        pass


class EventBus:
    """
    Event bus for publishing and subscribing to events.
    
    Provides async event handling with type-safe event distribution
    across GAuth components for audit, compliance, and monitoring.
    """
    
    def __init__(self):
        self._handlers: Dict[EventType, List[EventHandler]] = {}
        self._subscribers: Dict[EventType, List[Callable[[Event], None]]] = {}
        self._running = False
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._processor_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the event bus."""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
    
    async def stop(self) -> None:
        """Stop the event bus."""
        if not self._running:
            return
        
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
    
    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe a handler to an event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    def subscribe_function(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """Subscribe a function to an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type."""
        if event_type in self._handlers:
            try:
                self._handlers[event_type].remove(handler)
            except ValueError:
                pass
    
    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        if not self._running:
            await self.start()
        
        await self._event_queue.put(event)
    
    async def _process_events(self) -> None:
        """Process events from the queue."""
        while self._running:
            try:
                # Wait for event with timeout to allow clean shutdown
                event = await asyncio.wait_for(self._event_queue.get(), timeout=0.1)
                await self._dispatch_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                # Log error but continue processing
                print(f"Error processing event: {e}")
    
    async def _dispatch_event(self, event: Event) -> None:
        """Dispatch event to all registered handlers."""
        # Dispatch to class-based handlers
        if event.type in self._handlers:
            for handler in self._handlers[event.type]:
                try:
                    await handler.handle(event)
                except Exception as e:
                    print(f"Error in event handler: {e}")
        
        # Dispatch to function-based subscribers
        if event.type in self._subscribers:
            for callback in self._subscribers[event.type]:
                try:
                    callback(event)
                except Exception as e:
                    print(f"Error in event subscriber: {e}")


class AuditEventHandler(EventHandler):
    """Event handler that logs events for audit purposes."""
    
    def __init__(self, audit_logger):
        self.audit_logger = audit_logger
    
    async def handle(self, event: Event) -> None:
        """Handle event by logging to audit system."""
        from ..core.types import AuditEvent
        
        audit_event = AuditEvent(
            event_type=event.type.value,
            actor_id=event.subject,
            action=event.action.value,
            resource=event.resource,
            timestamp=event.timestamp,
            details=event.metadata,
            result="success"  # Events are generally successful by nature
        )
        
        await self.audit_logger.log_event(audit_event)


# Legacy compatibility types
ServiceStarted = EventType.SERVICE_STARTED
ServiceStopped = EventType.SERVICE_STOPPED
ServiceError = EventType.SERVICE_ERROR

# Factory functions for common events
def create_auth_event(action: EventAction, client_id: str, metadata: Dict[str, Any] = None) -> Event:
    """Create an authentication event."""
    return Event(
        type=EventType.AUTH_REQUEST,
        action=action,
        subject=client_id,
        resource="authorization",
        metadata=metadata or {}
    )

def create_token_event(action: EventAction, client_id: str, token_id: str, metadata: Dict[str, Any] = None) -> Event:
    """Create a token event."""
    return Event(
        type=EventType.TOKEN_ISSUED,
        action=action,
        subject=client_id,
        resource=f"token:{token_id}",
        metadata=metadata or {}
    )

def create_transaction_event(action: EventAction, client_id: str, transaction_id: str, metadata: Dict[str, Any] = None) -> Event:
    """Create a transaction event."""
    return Event(
        type=EventType.TRANSACTION_START,
        action=action,
        subject=client_id,
        resource=f"transaction:{transaction_id}",
        metadata=metadata or {}
    )