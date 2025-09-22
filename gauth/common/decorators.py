"""
Common decorators for GAuth framework.
"""

import asyncio
import functools
import logging
import time
from typing import Any, Callable, Optional, TypeVar, Union

from .utils import generate_request_id

F = TypeVar('F', bound=Callable[..., Any])

logger = logging.getLogger(__name__)


def with_request_id(func: F) -> F:
    """
    Decorator to add request ID to function calls.
    """
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        if 'request_id' not in kwargs:
            kwargs['request_id'] = generate_request_id()
        return await func(*args, **kwargs)
    
    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        if 'request_id' not in kwargs:
            kwargs['request_id'] = generate_request_id()
        return func(*args, **kwargs)
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


def log_execution_time(logger_instance: Optional[logging.Logger] = None):
    """
    Decorator to log function execution time.
    
    Args:
        logger_instance: Optional logger instance to use
    """
    def decorator(func: F) -> F:
        log = logger_instance or logger
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                execution_time = time.time() - start_time
                log.info(f"{func.__name__} executed in {execution_time:.3f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                log.error(f"{func.__name__} failed after {execution_time:.3f}s: {e}")
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                log.info(f"{func.__name__} executed in {execution_time:.3f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                log.error(f"{func.__name__} failed after {execution_time:.3f}s: {e}")
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


def catch_and_log_exceptions(
    default_return: Any = None,
    logger_instance: Optional[logging.Logger] = None,
    reraise: bool = True
):
    """
    Decorator to catch and log exceptions.
    
    Args:
        default_return: Default value to return on exception
        logger_instance: Optional logger instance to use
        reraise: Whether to reraise the exception after logging
    """
    def decorator(func: F) -> F:
        log = logger_instance or logger
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                log.exception(f"Exception in {func.__name__}: {e}")
                if reraise:
                    raise
                return default_return
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log.exception(f"Exception in {func.__name__}: {e}")
                if reraise:
                    raise
                return default_return
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


def deprecated(reason: str = "This function is deprecated"):
    """
    Decorator to mark functions as deprecated.
    
    Args:
        reason: Reason for deprecation
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import warnings
            warnings.warn(
                f"{func.__name__} is deprecated. {reason}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_types(**expected_types):
    """
    Decorator to validate function argument types.
    
    Args:
        **expected_types: Mapping of argument names to expected types
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get function signature
            import inspect
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Validate types
            for arg_name, expected_type in expected_types.items():
                if arg_name in bound_args.arguments:
                    value = bound_args.arguments[arg_name]
                    if value is not None and not isinstance(value, expected_type):
                        raise TypeError(
                            f"{func.__name__}() argument '{arg_name}' must be {expected_type.__name__}, "
                            f"got {type(value).__name__}"
                        )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def rate_limit(calls: int, period: int):
    """
    Simple rate limiting decorator.
    
    Args:
        calls: Number of calls allowed
        period: Period in seconds
    """
    def decorator(func: F) -> F:
        call_times = []
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            
            # Remove old calls outside the period
            call_times[:] = [call_time for call_time in call_times if now - call_time < period]
            
            # Check if we've exceeded the rate limit
            if len(call_times) >= calls:
                sleep_time = period - (now - call_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    # Update now after sleeping
                    now = time.time()
                    call_times[:] = [call_time for call_time in call_times if now - call_time < period]
            
            # Record this call
            call_times.append(now)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def memoize(maxsize: int = 128):
    """
    Memoization decorator with configurable cache size.
    
    Args:
        maxsize: Maximum cache size
    """
    def decorator(func: F) -> F:
        cache = {}
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from arguments
            key = str(args) + str(sorted(kwargs.items()))
            
            if key in cache:
                return cache[key]
            
            result = func(*args, **kwargs)
            
            # Manage cache size
            if len(cache) >= maxsize:
                # Remove oldest item (simple FIFO)
                oldest_key = next(iter(cache))
                del cache[oldest_key]
            
            cache[key] = result
            return result
        
        # Add cache management methods
        wrapper.cache_clear = lambda: cache.clear()
        wrapper.cache_info = lambda: {"hits": 0, "misses": 0, "size": len(cache), "maxsize": maxsize}
        
        return wrapper
    return decorator


def singleton(cls):
    """
    Singleton decorator for classes.
    """
    instances = {}
    
    @functools.wraps(cls)
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    
    return get_instance


def require_auth(permission: Optional[str] = None):
    """
    Decorator to require authentication and optional permission.
    
    Args:
        permission: Optional permission required
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract context from kwargs or args
            context = kwargs.get('context') or (args[0] if args and hasattr(args[0], 'user') else None)
            
            if not context or not getattr(context, 'user', None):
                raise PermissionError("Authentication required")
            
            if permission and not getattr(context.user, 'has_permission', lambda x: False)(permission):
                raise PermissionError(f"Permission '{permission}' required")
            
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Extract context from kwargs or args
            context = kwargs.get('context') or (args[0] if args and hasattr(args[0], 'user') else None)
            
            if not context or not getattr(context, 'user', None):
                raise PermissionError("Authentication required")
            
            if permission and not getattr(context.user, 'has_permission', lambda x: False)(permission):
                raise PermissionError(f"Permission '{permission}' required")
            
            return func(*args, **kwargs)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator