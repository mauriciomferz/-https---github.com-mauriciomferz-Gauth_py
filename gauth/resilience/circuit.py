"""
Circuit breaker integration with resilience patterns.
"""

import asyncio
import logging
from typing import Callable, Any

from ..circuit import CircuitBreaker, CircuitBreakerOptions, CircuitBreakerOpenError
from .patterns import Retry, RetryConfig, Timeout, TimeoutConfig

logger = logging.getLogger(__name__)


class CircuitBreakerRetry:
    """Combine circuit breaker with retry logic."""
    
    def __init__(self, circuit_options: CircuitBreakerOptions, retry_config: RetryConfig):
        self.circuit = CircuitBreaker(circuit_options)
        self.retry_handler = Retry(retry_config)
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker and retry protection."""
        async def circuit_protected_func():
            return await self.circuit.call(func, *args, **kwargs)
        
        try:
            return await self.retry_handler.execute(circuit_protected_func)
        except CircuitBreakerOpenError:
            # Don't retry if circuit breaker is open
            logger.warning(f"Circuit breaker '{self.circuit.name}' is open, not retrying")
            raise
    
    def execute_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker and retry protection (synchronous)."""
        def circuit_protected_func():
            return self.circuit.call_sync(func, *args, **kwargs)
        
        try:
            return self.retry_handler.execute_sync(circuit_protected_func)
        except CircuitBreakerOpenError:
            # Don't retry if circuit breaker is open
            logger.warning(f"Circuit breaker '{self.circuit.name}' is open, not retrying")
            raise


async def resilient_call(
    func: Callable,
    *args,
    circuit_options: CircuitBreakerOptions = None,
    retry_config: RetryConfig = None,
    timeout_config: TimeoutConfig = None,
    **kwargs
) -> Any:
    """
    Make a resilient call with optional circuit breaker, retry, and timeout.
    """
    # Start with the original function
    protected_func = func
    
    # Apply timeout if configured
    if timeout_config:
        timeout_handler = Timeout(timeout_config)
        original_func = protected_func
        
        async def timeout_protected():
            return await timeout_handler.execute(original_func, *args, **kwargs)
        
        protected_func = timeout_protected
        args = ()  # Args already bound in timeout_protected
        kwargs = {}
    
    # Apply circuit breaker if configured
    if circuit_options:
        circuit = CircuitBreaker(circuit_options)
        original_func = protected_func
        
        async def circuit_protected():
            return await circuit.call(original_func, *args, **kwargs)
        
        protected_func = circuit_protected
        args = ()  # Args already bound in circuit_protected
        kwargs = {}
    
    # Apply retry if configured
    if retry_config:
        retry_handler = Retry(retry_config)
        return await retry_handler.execute(protected_func, *args, **kwargs)
    else:
        # No retry, just execute
        if asyncio.iscoroutinefunction(protected_func):
            return await protected_func(*args, **kwargs)
        else:
            return protected_func(*args, **kwargs)