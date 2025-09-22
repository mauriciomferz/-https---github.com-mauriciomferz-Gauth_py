"""
HTTP middleware for rate limiting in GAuth applications.

This module provides middleware for various web frameworks to automatically
apply rate limiting to HTTP requests based on different criteria.
"""

import asyncio
import time
import logging
from typing import Callable, Optional, Any, Dict, Union
from functools import wraps

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from fastapi import Request, Response, HTTPException
    from starlette.middleware.base import BaseHTTPMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from flask import Flask, request, jsonify, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from .limiter import RateLimiter, RateLimitQuota, RateLimitExceeded, create_rate_limiter
from .redis_limiter import create_redis_rate_limiter
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class RateLimitMiddleware:
    """Base rate limiting middleware."""
    
    def __init__(self,
                 rate_limiter: RateLimiter = None,
                 rate: int = 100,
                 window: float = 60.0,
                 algorithm: str = "token_bucket",
                 backend: str = "memory",
                 redis_url: Optional[str] = None,
                 identifier_func: Optional[Callable] = None,
                 skip_func: Optional[Callable] = None,
                 on_rate_limit: Optional[Callable] = None):
        """
        Initialize rate limiting middleware.
        
        Args:
            rate_limiter: Custom rate limiter instance
            rate: Number of requests per window
            window: Time window in seconds
            algorithm: Rate limiting algorithm
            backend: Backend type (memory, redis)
            redis_url: Redis connection URL
            identifier_func: Function to extract identifier from request
            skip_func: Function to determine if rate limiting should be skipped
            on_rate_limit: Function called when rate limit is exceeded
        """
        if rate_limiter:
            self.rate_limiter = rate_limiter
        elif backend == "redis":
            from .redis_limiter import RateLimitConfig
            config = RateLimitConfig(
                rate=rate,
                window=window,
                backend=backend,
                redis_url=redis_url
            )
            self.rate_limiter = create_redis_rate_limiter(algorithm, config)
        else:
            from .limiter import RateLimitConfig
            config = RateLimitConfig(rate=rate, window=window, backend=backend)
            self.rate_limiter = create_rate_limiter(algorithm, config)
        
        self.identifier_func = identifier_func or self._default_identifier
        self.skip_func = skip_func
        self.on_rate_limit = on_rate_limit or self._default_on_rate_limit
    
    def _default_identifier(self, request) -> str:
        """Default identifier extraction (IP address)."""
        # This will be implemented differently for each framework
        return "default"
    
    async def _default_on_rate_limit(self, quota: RateLimitQuota, request) -> Any:
        """Default rate limit exceeded handler."""
        headers = {
            'X-RateLimit-Limit': str(self.rate_limiter.config.rate),
            'X-RateLimit-Remaining': str(quota.remaining),
            'X-RateLimit-Reset': str(int(quota.reset_time.timestamp())),
        }
        
        if quota.retry_after:
            headers['Retry-After'] = str(int(quota.retry_after))
        
        return headers
    
    async def _check_rate_limit(self, request) -> Optional[Dict[str, str]]:
        """Check rate limit for request."""
        try:
            # Skip rate limiting if skip function returns True
            if self.skip_func and self.skip_func(request):
                return None
            
            # Get identifier
            identifier = self.identifier_func(request)
            
            # Check rate limit
            quota = await self.rate_limiter.allow(identifier)
            
            # Set rate limit headers
            headers = {
                'X-RateLimit-Limit': str(self.rate_limiter.config.rate),
                'X-RateLimit-Remaining': str(quota.remaining),
                'X-RateLimit-Reset': str(int(quota.reset_time.timestamp())),
            }
            
            if not quota.allowed:
                # Rate limit exceeded
                if quota.retry_after:
                    headers['Retry-After'] = str(int(quota.retry_after))
                
                # Call custom handler
                custom_headers = await self.on_rate_limit(quota, request)
                if isinstance(custom_headers, dict):
                    headers.update(custom_headers)
                
                return headers
            
            return headers
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # On error, allow request but log the issue
            return None


class AioHttpRateLimitMiddleware(RateLimitMiddleware):
    """Rate limiting middleware for aiohttp."""
    
    def __init__(self, **kwargs):
        """Initialize aiohttp rate limiting middleware."""
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for AioHttpRateLimitMiddleware")
        super().__init__(**kwargs)
    
    def _default_identifier(self, request: web.Request) -> str:
        """Extract identifier from aiohttp request."""
        # Try to get real IP from headers (if behind proxy)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fallback to remote address
        return request.remote
    
    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        """aiohttp middleware handler."""
        # Check rate limit
        rate_limit_headers = await self._check_rate_limit(request)
        
        if rate_limit_headers and 'Retry-After' in rate_limit_headers:
            # Rate limit exceeded
            return web.Response(
                status=429,
                headers=rate_limit_headers,
                text='Rate limit exceeded'
            )
        
        # Process request
        response = await handler(request)
        
        # Add rate limit headers to response
        if rate_limit_headers:
            for key, value in rate_limit_headers.items():
                response.headers[key] = value
        
        return response


class FastAPIRateLimitMiddleware(BaseHTTPMiddleware, RateLimitMiddleware):
    """Rate limiting middleware for FastAPI."""
    
    def __init__(self, app, **kwargs):
        """Initialize FastAPI rate limiting middleware."""
        if not FASTAPI_AVAILABLE:
            raise ImportError("fastapi is required for FastAPIRateLimitMiddleware")
        
        RateLimitMiddleware.__init__(self, **kwargs)
        BaseHTTPMiddleware.__init__(self, app)
    
    def _default_identifier(self, request: Request) -> str:
        """Extract identifier from FastAPI request."""
        # Try to get real IP from headers
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fallback to client host
        return str(request.client.host) if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """FastAPI middleware handler."""
        # Check rate limit
        rate_limit_headers = await self._check_rate_limit(request)
        
        if rate_limit_headers and 'Retry-After' in rate_limit_headers:
            # Rate limit exceeded
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers=rate_limit_headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        if rate_limit_headers:
            for key, value in rate_limit_headers.items():
                response.headers[key] = value
        
        return response


class FlaskRateLimitMiddleware(RateLimitMiddleware):
    """Rate limiting middleware for Flask."""
    
    def __init__(self, app: Optional['Flask'] = None, **kwargs):
        """Initialize Flask rate limiting middleware."""
        if not FLASK_AVAILABLE:
            raise ImportError("flask is required for FlaskRateLimitMiddleware")
        
        super().__init__(**kwargs)
        self.app = app
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: 'Flask') -> None:
        """Initialize middleware with Flask app."""
        app.before_request(self._before_request)
        app.after_request(self._after_request)
    
    def _default_identifier(self, request) -> str:
        """Extract identifier from Flask request."""
        # Try to get real IP from headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fallback to remote address
        return request.remote_addr or "unknown"
    
    def _before_request(self) -> Optional[Any]:
        """Flask before request handler."""
        try:
            # Convert async call to sync (Flask doesn't support async)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            rate_limit_headers = loop.run_until_complete(
                self._check_rate_limit(request)
            )
            
            g.rate_limit_headers = rate_limit_headers
            
            if rate_limit_headers and 'Retry-After' in rate_limit_headers:
                # Rate limit exceeded
                response = jsonify({"error": "Rate limit exceeded"})
                response.status_code = 429
                for key, value in rate_limit_headers.items():
                    response.headers[key] = value
                return response
                
        except Exception as e:
            logger.error(f"Flask rate limiting error: {e}")
        
        return None
    
    def _after_request(self, response) -> Any:
        """Flask after request handler."""
        # Add rate limit headers to response
        if hasattr(g, 'rate_limit_headers') and g.rate_limit_headers:
            for key, value in g.rate_limit_headers.items():
                if key != 'Retry-After':  # Don't add retry-after on success
                    response.headers[key] = value
        
        return response


# Decorator for function-level rate limiting
def rate_limit(rate: int = 100,
              window: float = 60.0,
              algorithm: str = "token_bucket",
              backend: str = "memory",
              redis_url: Optional[str] = None,
              identifier_func: Optional[Callable] = None,
              per_user: bool = False):
    """
    Decorator to add rate limiting to any function.
    
    Args:
        rate: Number of requests per window
        window: Time window in seconds
        algorithm: Rate limiting algorithm
        backend: Backend type (memory, redis)
        redis_url: Redis connection URL
        identifier_func: Function to extract identifier
        per_user: Rate limit per user instead of globally
    
    Returns:
        Decorator function
    """
    # Create rate limiter
    if backend == "redis":
        from .redis_limiter import RateLimitConfig
        config = RateLimitConfig(
            rate=rate,
            window=window,
            backend=backend,
            redis_url=redis_url
        )
        limiter = create_redis_rate_limiter(algorithm, config)
    else:
        from .limiter import RateLimitConfig
        config = RateLimitConfig(rate=rate, window=window, backend=backend)
        limiter = create_rate_limiter(algorithm, config)
    
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                # Determine identifier
                if identifier_func:
                    identifier = identifier_func(*args, **kwargs)
                elif per_user and len(args) > 0:
                    # Try to extract user ID from first argument
                    identifier = getattr(args[0], 'user_id', str(args[0]))
                else:
                    identifier = func.__name__
                
                # Check rate limit
                quota = await limiter.allow(identifier)
                
                if not quota.allowed:
                    raise RateLimitExceeded(
                        f"Rate limit exceeded for {func.__name__}",
                        retry_after=quota.retry_after,
                        remaining=quota.remaining
                    )
                
                return await func(*args, **kwargs)
            
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                # For sync functions, run in event loop
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                # Determine identifier
                if identifier_func:
                    identifier = identifier_func(*args, **kwargs)
                elif per_user and len(args) > 0:
                    identifier = getattr(args[0], 'user_id', str(args[0]))
                else:
                    identifier = func.__name__
                
                # Check rate limit
                quota = loop.run_until_complete(limiter.allow(identifier))
                
                if not quota.allowed:
                    raise RateLimitExceeded(
                        f"Rate limit exceeded for {func.__name__}",
                        retry_after=quota.retry_after,
                        remaining=quota.remaining
                    )
                
                return func(*args, **kwargs)
            
            return sync_wrapper
    
    return decorator


# Convenience functions
def create_aiohttp_rate_limit_middleware(**kwargs) -> Callable:
    """Create aiohttp rate limiting middleware."""
    middleware = AioHttpRateLimitMiddleware(**kwargs)
    return middleware.middleware


def create_fastapi_rate_limit_middleware(**kwargs) -> type:
    """Create FastAPI rate limiting middleware class."""
    class MiddlewareClass(FastAPIRateLimitMiddleware):
        def __init__(self, app):
            super().__init__(app, **kwargs)
    
    return MiddlewareClass


def create_flask_rate_limit_middleware(app: 'Flask' = None, **kwargs) -> FlaskRateLimitMiddleware:
    """Create Flask rate limiting middleware."""
    return FlaskRateLimitMiddleware(app, **kwargs)