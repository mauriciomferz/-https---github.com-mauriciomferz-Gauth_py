"""
Resilience patterns implementation for fault tolerance.
"""

import asyncio
import logging
import random
import time
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional, Union, List, Type
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class RetryConfig:
    """Retry configuration."""
    max_attempts: int = 3
    initial_delay: timedelta = field(default_factory=lambda: timedelta(seconds=1))
    max_delay: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    multiplier: float = 2.0
    jitter: bool = True
    retryable_exceptions: List[Type[Exception]] = field(default_factory=lambda: [Exception])
    
    def __post_init__(self):
        if not self.retryable_exceptions:
            self.retryable_exceptions = [Exception]


# Legacy alias for compatibility
RetryStrategy = RetryConfig


class Retry:
    """Retry handler with configurable backoff strategies."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self._attempt_count = 0
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                self._attempt_count = attempt
                
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                if attempt > 1:
                    logger.info(f"Function succeeded on attempt {attempt}")
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                if not self._is_retryable(e):
                    logger.warning(f"Non-retryable exception: {e}")
                    raise
                
                # If this was the last attempt, raise the exception
                if attempt == self.config.max_attempts:
                    logger.error(f"Function failed after {attempt} attempts: {e}")
                    raise
                
                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s")
                
                await asyncio.sleep(delay)
        
        # This shouldn't be reached, but just in case
        if last_exception:
            raise last_exception
    
    def execute_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic (synchronous)."""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                self._attempt_count = attempt
                result = func(*args, **kwargs)
                
                if attempt > 1:
                    logger.info(f"Function succeeded on attempt {attempt}")
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                if not self._is_retryable(e):
                    logger.warning(f"Non-retryable exception: {e}")
                    raise
                
                # If this was the last attempt, raise the exception
                if attempt == self.config.max_attempts:
                    logger.error(f"Function failed after {attempt} attempts: {e}")
                    raise
                
                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s")
                
                time.sleep(delay)
        
        # This shouldn't be reached, but just in case
        if last_exception:
            raise last_exception
    
    def _is_retryable(self, exception: Exception) -> bool:
        """Check if exception is retryable."""
        return any(isinstance(exception, exc_type) for exc_type in self.config.retryable_exceptions)
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for the given attempt."""
        # Base delay with exponential backoff
        delay_seconds = self.config.initial_delay.total_seconds() * (self.config.multiplier ** (attempt - 1))
        
        # Apply maximum delay limit
        max_delay_seconds = self.config.max_delay.total_seconds()
        delay_seconds = min(delay_seconds, max_delay_seconds)
        
        # Add jitter if enabled
        if self.config.jitter:
            jitter_factor = random.uniform(0.5, 1.5)
            delay_seconds *= jitter_factor
        
        return delay_seconds


@dataclass 
class TimeoutConfig:
    """Timeout configuration."""
    timeout: timedelta
    on_timeout: Optional[Callable[[float], None]] = None


class Timeout:
    """Timeout handler."""
    
    def __init__(self, config: TimeoutConfig):
        self.config = config
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout."""
        timeout_seconds = self.config.timeout.total_seconds()
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            else:
                # For sync functions, run in executor with timeout
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: func(*args, **kwargs)),
                    timeout=timeout_seconds
                )
            return result
            
        except asyncio.TimeoutError:
            if self.config.on_timeout:
                self.config.on_timeout(timeout_seconds)
            raise TimeoutError(f"Operation timed out after {timeout_seconds}s")


class BulkheadFullError(Exception):
    """Exception raised when bulkhead is full."""
    pass


@dataclass
class BulkheadConfig:
    """Bulkhead configuration."""
    name: str
    max_concurrent: int
    max_queue_size: int = 0
    timeout: Optional[timedelta] = None


class Bulkhead:
    """Bulkhead pattern for resource isolation."""
    
    def __init__(self, config: BulkheadConfig):
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        self._sync_semaphore = threading.Semaphore(config.max_concurrent)
        self._queue = asyncio.Queue(maxsize=config.max_queue_size)
        self._active_count = 0
        self._total_requests = 0
        self._rejected_requests = 0
        self._lock = threading.Lock()
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function within bulkhead constraints."""
        self._total_requests += 1
        
        timeout_seconds = self.config.timeout.total_seconds() if self.config.timeout else None
        
        try:
            # Try to acquire semaphore
            if timeout_seconds:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=timeout_seconds)
            else:
                await self._semaphore.acquire()
            
            try:
                self._active_count += 1
                
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, lambda: func(*args, **kwargs))
                
                return result
                
            finally:
                self._active_count -= 1
                self._semaphore.release()
                
        except asyncio.TimeoutError:
            self._rejected_requests += 1
            raise BulkheadFullError(f"Bulkhead '{self.config.name}' timed out")
    
    def execute_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function within bulkhead constraints (synchronous)."""
        self._total_requests += 1
        
        timeout_seconds = self.config.timeout.total_seconds() if self.config.timeout else None
        
        acquired = self._sync_semaphore.acquire(timeout=timeout_seconds)
        if not acquired:
            self._rejected_requests += 1
            raise BulkheadFullError(f"Bulkhead '{self.config.name}' is full")
        
        try:
            self._active_count += 1
            return func(*args, **kwargs)
        finally:
            self._active_count -= 1
            self._sync_semaphore.release()
    
    def get_stats(self) -> dict:
        """Get bulkhead statistics."""
        return {
            'name': self.config.name,
            'max_concurrent': self.config.max_concurrent,
            'active_count': self._active_count,
            'total_requests': self._total_requests,
            'rejected_requests': self._rejected_requests,
            'available_permits': self._semaphore._value
        }


class RateLimitExceededError(Exception):
    """Exception raised when rate limit is exceeded."""
    pass


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float
    burst_size: Optional[int] = None
    window_size: timedelta = field(default_factory=lambda: timedelta(seconds=1))


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.burst_size = config.burst_size or int(config.requests_per_second)
        self._tokens = float(self.burst_size)
        self._last_update = time.time()
        self._lock = threading.Lock()
    
    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens."""
        with self._lock:
            now = time.time()
            
            # Add tokens based on elapsed time
            elapsed = now - self._last_update
            tokens_to_add = elapsed * self.config.requests_per_second
            self._tokens = min(self.burst_size, self._tokens + tokens_to_add)
            self._last_update = now
            
            # Check if we have enough tokens
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            
            return False
    
    async def wait_for_token(self, tokens: int = 1) -> None:
        """Wait until tokens are available."""
        while not self.acquire(tokens):
            await asyncio.sleep(0.01)  # Small delay to prevent busy waiting
    
    def wait_for_token_sync(self, tokens: int = 1) -> None:
        """Wait until tokens are available (synchronous)."""
        while not self.acquire(tokens):
            time.sleep(0.01)  # Small delay to prevent busy waiting


# Backoff strategies
def exponential_backoff(attempt: int, initial_delay: float = 1.0, multiplier: float = 2.0, max_delay: float = 60.0) -> float:
    """Calculate exponential backoff delay."""
    delay = initial_delay * (multiplier ** (attempt - 1))
    return min(delay, max_delay)


def linear_backoff(attempt: int, initial_delay: float = 1.0, increment: float = 1.0, max_delay: float = 60.0) -> float:
    """Calculate linear backoff delay."""
    delay = initial_delay + ((attempt - 1) * increment)
    return min(delay, max_delay)


def fixed_backoff(attempt: int, delay: float = 1.0) -> float:
    """Calculate fixed backoff delay."""
    return delay


# Decorators
def retry(config: RetryConfig):
    """Retry decorator."""
    def decorator(func: Callable):
        retry_handler = Retry(config)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await retry_handler.execute(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return retry_handler.execute_sync(func, *args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_timeout(config: TimeoutConfig):
    """Timeout decorator."""
    def decorator(func: Callable):
        timeout_handler = Timeout(config)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await timeout_handler.execute(func, *args, **kwargs)
        
        return wrapper
    
    return decorator


def with_bulkhead(config: BulkheadConfig):
    """Bulkhead decorator."""
    bulkhead = Bulkhead(config)
    
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await bulkhead.execute(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return bulkhead.execute_sync(func, *args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_rate_limit(config: RateLimitConfig):
    """Rate limiting decorator."""
    rate_limiter = RateLimiter(config)
    
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            await rate_limiter.wait_for_token()
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            rate_limiter.wait_for_token_sync()
            return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator