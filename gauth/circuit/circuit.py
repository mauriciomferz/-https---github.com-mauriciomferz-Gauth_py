"""
Circuit breaker implementation for preventing cascading failures.
"""

import asyncio
import logging
import time
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, Dict, Union

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests allowed
    OPEN = "open"          # Failure mode, requests blocked
    HALF_OPEN = "half_open"  # Testing mode, limited requests allowed


@dataclass
class StateTransition:
    """Circuit breaker state transition."""
    from_state: CircuitState
    to_state: CircuitState
    timestamp: datetime
    reason: str
    failure_count: int = 0
    success_count: int = 0


@dataclass
class CircuitStats:
    """Circuit breaker statistics."""
    name: str
    state: CircuitState
    failure_count: int = 0
    success_count: int = 0
    total_requests: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    state_change_time: datetime = field(default_factory=datetime.utcnow)
    failure_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'total_requests': self.total_requests,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_success_time': self.last_success_time.isoformat() if self.last_success_time else None,
            'state_change_time': self.state_change_time.isoformat(),
            'failure_rate': self.failure_rate
        }


@dataclass
class CircuitBreakerOptions:
    """Circuit breaker configuration options."""
    name: str
    failure_threshold: int = 5
    reset_timeout: timedelta = field(default_factory=lambda: timedelta(seconds=60))
    half_open_limit: int = 1
    success_threshold: int = 1  # Successes needed to close from half-open
    failure_timeout: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    on_state_change: Optional[Callable[[StateTransition], None]] = None
    monitor_interval: timedelta = field(default_factory=lambda: timedelta(seconds=10))


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open."""
    
    def __init__(self, circuit_name: str, message: str = None):
        self.circuit_name = circuit_name
        default_message = f"Circuit breaker '{circuit_name}' is open"
        super().__init__(message or default_message)


class CircuitBreakerError(Exception):
    """Base exception for circuit breaker errors."""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation to prevent cascading failures.
    
    States:
    - CLOSED: Normal operation, all requests allowed
    - OPEN: Failure mode, all requests blocked  
    - HALF_OPEN: Testing mode, limited requests allowed to test recovery
    """
    
    def __init__(self, options: CircuitBreakerOptions):
        self.options = options
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._total_requests = 0
        self._last_failure_time: Optional[datetime] = None
        self._last_success_time: Optional[datetime] = None
        self._state_change_time = datetime.utcnow()
        self._half_open_requests = 0
        self._lock = threading.RLock()
        self._transitions: list[StateTransition] = []
        
        logger.info(f"Circuit breaker '{self.name}' initialized")
    
    @property
    def name(self) -> str:
        """Get circuit breaker name."""
        return self.options.name
    
    @property
    def state(self) -> CircuitState:
        """Get current state."""
        with self._lock:
            return self._state
    
    @property
    def stats(self) -> CircuitStats:
        """Get current statistics."""
        with self._lock:
            failure_rate = 0.0
            if self._total_requests > 0:
                failure_rate = self._failure_count / self._total_requests
            
            return CircuitStats(
                name=self.name,
                state=self._state,
                failure_count=self._failure_count,
                success_count=self._success_count,
                total_requests=self._total_requests,
                last_failure_time=self._last_failure_time,
                last_success_time=self._last_success_time,
                state_change_time=self._state_change_time,
                failure_rate=failure_rate
            )
    
    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self._lock:
            old_state = self._state
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_requests = 0
            self._state_change_time = datetime.utcnow()
            
            self._record_transition(old_state, CircuitState.CLOSED, "Manual reset")
            
        logger.info(f"Circuit breaker '{self.name}' manually reset")
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        return await self._execute_async(func, args, kwargs)
    
    def call_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection (synchronous)."""
        return self._execute_sync(func, args, kwargs)
    
    async def _execute_async(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute async function with circuit protection."""
        if not self._can_execute():
            raise CircuitBreakerOpenError(self.name)
        
        start_time = time.time()
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            execution_time = time.time() - start_time
            self._on_success(execution_time)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._on_failure(e, execution_time)
            raise
    
    def _execute_sync(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute sync function with circuit protection."""
        if not self._can_execute():
            raise CircuitBreakerOpenError(self.name)
        
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            self._on_success(execution_time)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._on_failure(e, execution_time)
            raise
    
    def _can_execute(self) -> bool:
        """Check if request can be executed."""
        with self._lock:
            self._total_requests += 1
            
            if self._state == CircuitState.CLOSED:
                return True
            
            elif self._state == CircuitState.OPEN:
                # Check if enough time has passed to transition to half-open
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                    return True
                return False
            
            elif self._state == CircuitState.HALF_OPEN:
                # Allow limited requests in half-open state
                if self._half_open_requests < self.options.half_open_limit:
                    self._half_open_requests += 1
                    return True
                return False
            
            return False
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt reset."""
        if self._state != CircuitState.OPEN:
            return False
        
        if not self._last_failure_time:
            return True
        
        time_since_failure = datetime.utcnow() - self._last_failure_time
        return time_since_failure >= self.options.reset_timeout
    
    def _on_success(self, execution_time: float) -> None:
        """Handle successful execution."""
        with self._lock:
            self._success_count += 1
            self._last_success_time = datetime.utcnow()
            
            if self._state == CircuitState.HALF_OPEN:
                # Check if we should close the circuit
                if self._success_count >= self.options.success_threshold:
                    self._transition_to_closed()
            
        logger.debug(f"Circuit breaker '{self.name}' recorded success (time: {execution_time:.3f}s)")
    
    def _on_failure(self, exception: Exception, execution_time: float) -> None:
        """Handle failed execution."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.utcnow()
            
            if self._state == CircuitState.CLOSED:
                # Check if we should open the circuit
                if self._failure_count >= self.options.failure_threshold:
                    self._transition_to_open()
            
            elif self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open state opens the circuit
                self._transition_to_open()
        
        logger.warning(f"Circuit breaker '{self.name}' recorded failure: {exception} (time: {execution_time:.3f}s)")
    
    def _transition_to_open(self) -> None:
        """Transition to open state."""
        old_state = self._state
        self._state = CircuitState.OPEN
        self._state_change_time = datetime.utcnow()
        self._half_open_requests = 0
        
        reason = f"Failure threshold exceeded ({self._failure_count} failures)"
        self._record_transition(old_state, CircuitState.OPEN, reason)
        
        logger.warning(f"Circuit breaker '{self.name}' opened: {reason}")
    
    def _transition_to_half_open(self) -> None:
        """Transition to half-open state."""
        old_state = self._state
        self._state = CircuitState.HALF_OPEN
        self._state_change_time = datetime.utcnow()
        self._half_open_requests = 0
        self._success_count = 0  # Reset success count for half-open evaluation
        
        reason = "Reset timeout elapsed, attempting recovery"
        self._record_transition(old_state, CircuitState.HALF_OPEN, reason)
        
        logger.info(f"Circuit breaker '{self.name}' half-opened: {reason}")
    
    def _transition_to_closed(self) -> None:
        """Transition to closed state."""
        old_state = self._state
        self._state = CircuitState.CLOSED
        self._state_change_time = datetime.utcnow()
        self._failure_count = 0  # Reset failure count
        self._half_open_requests = 0
        
        reason = f"Recovery successful ({self._success_count} successes)"
        self._record_transition(old_state, CircuitState.CLOSED, reason)
        
        logger.info(f"Circuit breaker '{self.name}' closed: {reason}")
    
    def _record_transition(self, from_state: CircuitState, to_state: CircuitState, reason: str) -> None:
        """Record state transition."""
        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            timestamp=datetime.utcnow(),
            reason=reason,
            failure_count=self._failure_count,
            success_count=self._success_count
        )
        
        self._transitions.append(transition)
        
        # Keep only recent transitions
        if len(self._transitions) > 100:
            self._transitions = self._transitions[-50:]
        
        # Call state change callback if provided
        if self.options.on_state_change:
            try:
                self.options.on_state_change(transition)
            except Exception as e:
                logger.error(f"State change callback failed: {e}")
    
    def get_transitions(self) -> list[StateTransition]:
        """Get state transition history."""
        with self._lock:
            return self._transitions.copy()


@contextmanager
def with_circuit_breaker(circuit: CircuitBreaker):
    """Context manager for circuit breaker protection."""
    def protected_call(func: Callable, *args, **kwargs):
        return circuit.call_sync(func, *args, **kwargs)
    
    yield protected_call


@asynccontextmanager
async def with_circuit_breaker_async(circuit: CircuitBreaker):
    """Async context manager for circuit breaker protection."""
    async def protected_call(func: Callable, *args, **kwargs):
        return await circuit.call(func, *args, **kwargs)
    
    yield protected_call


def circuit_breaker(options: CircuitBreakerOptions):
    """Decorator for circuit breaker protection."""
    circuit = CircuitBreaker(options)
    
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await circuit.call(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return circuit.call_sync(func, *args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator