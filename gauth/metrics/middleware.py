"""
HTTP middleware for metrics collection in GAuth applications.

This module provides middleware for various web frameworks to automatically
collect HTTP request metrics including timing, status codes, and response sizes.
"""

import time
import asyncio
import logging
from typing import Callable, Optional, Any, Dict
from functools import wraps

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from flask import Flask, request, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from .collector import MetricsCollector, get_global_collector
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class BaseMetricsMiddleware:
    """Base class for metrics middleware."""
    
    def __init__(self, 
                 collector: MetricsCollector = None,
                 handler_name: str = "default",
                 track_auth: bool = False,
                 track_authz: bool = False):
        """
        Initialize base metrics middleware.
        
        Args:
            collector: Metrics collector instance
            handler_name: Name for the handler in metrics labels
            track_auth: Track authentication metrics
            track_authz: Track authorization metrics
        """
        self.collector = collector or get_global_collector()
        self.handler_name = handler_name
        self.track_auth = track_auth
        self.track_authz = track_authz
    
    async def _record_request_metrics(self, 
                                    method: str, 
                                    status: str, 
                                    duration: float, 
                                    response_size: int,
                                    headers: Dict[str, str] = None) -> None:
        """Record metrics for an HTTP request."""
        headers = headers or {}
        
        # Record basic HTTP metrics
        await self.collector.record_http_request(
            self.handler_name, method, status, duration, response_size
        )
        
        # Record authentication metrics if enabled
        if self.track_auth and "x-auth-method" in headers:
            auth_method = headers["x-auth-method"]
            await self.collector.record_auth_attempt(auth_method, status)
            await self.collector.observe_auth_latency(auth_method, duration)
        
        # Record authorization metrics if enabled
        if self.track_authz and "x-policy" in headers:
            policy = headers["x-policy"]
            allowed = status == "200"
            await self.collector.record_authz_decision(allowed, policy)
            await self.collector.observe_authz_latency(policy, duration)


class AioHttpMetricsMiddleware(BaseMetricsMiddleware):
    """Metrics middleware for aiohttp applications."""
    
    def __init__(self, **kwargs):
        """Initialize aiohttp middleware."""
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for AioHttpMetricsMiddleware")
        super().__init__(**kwargs)
    
    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        """aiohttp middleware handler."""
        start_time = time.time()
        
        # Increment active requests
        await self.collector.inc_active_requests(self.handler_name)
        
        try:
            # Process request
            response = await handler(request)
            
            # Calculate metrics
            duration = time.time() - start_time
            status = str(response.status)
            method = request.method
            
            # Get response size
            response_size = 0
            if hasattr(response, 'body') and response.body:
                response_size = len(response.body)
            elif hasattr(response, 'text'):
                try:
                    text = await response.text()
                    response_size = len(text.encode('utf-8'))
                except:
                    response_size = 0
            
            # Get headers for auth/authz tracking
            headers = {k.lower(): v for k, v in request.headers.items()}
            
            # Record metrics
            await self._record_request_metrics(
                method, status, duration, response_size, headers
            )
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            await self._record_request_metrics(
                request.method, "500", duration, 0
            )
            raise
            
        finally:
            # Decrement active requests
            await self.collector.dec_active_requests(self.handler_name)


class FastAPIMetricsMiddleware(BaseHTTPMiddleware, BaseMetricsMiddleware):
    """Metrics middleware for FastAPI applications."""
    
    def __init__(self, app, **kwargs):
        """Initialize FastAPI middleware."""
        if not FASTAPI_AVAILABLE:
            raise ImportError("fastapi is required for FastAPIMetricsMiddleware")
        
        BaseMetricsMiddleware.__init__(self, **kwargs)
        BaseHTTPMiddleware.__init__(self, app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """FastAPI middleware handler."""
        start_time = time.time()
        
        # Increment active requests
        await self.collector.inc_active_requests(self.handler_name)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate metrics
            duration = time.time() - start_time
            status = str(response.status_code)
            method = request.method
            
            # Get response size (approximate)
            response_size = 0
            if hasattr(response, 'body'):
                response_size = len(response.body)
            
            # Get headers for auth/authz tracking
            headers = {k.lower(): v for k, v in request.headers.items()}
            
            # Record metrics
            await self._record_request_metrics(
                method, status, duration, response_size, headers
            )
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            await self._record_request_metrics(
                request.method, "500", duration, 0
            )
            raise
            
        finally:
            # Decrement active requests
            await self.collector.dec_active_requests(self.handler_name)


class FlaskMetricsMiddleware(BaseMetricsMiddleware):
    """Metrics middleware for Flask applications."""
    
    def __init__(self, app: Optional['Flask'] = None, **kwargs):
        """Initialize Flask middleware."""
        if not FLASK_AVAILABLE:
            raise ImportError("flask is required for FlaskMetricsMiddleware")
        
        super().__init__(**kwargs)
        self.app = app
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: 'Flask') -> None:
        """Initialize middleware with Flask app."""
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_appcontext(self._teardown)
    
    def _before_request(self) -> None:
        """Flask before request handler."""
        g.metrics_start_time = time.time()
        
        # Increment active requests (sync version)
        # Note: Flask doesn't support async, so we use a sync approach
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're in an async context, schedule the coroutine
                asyncio.create_task(
                    self.collector.inc_active_requests(self.handler_name)
                )
            else:
                # If not in async context, run it
                loop.run_until_complete(
                    self.collector.inc_active_requests(self.handler_name)
                )
        except RuntimeError:
            # No event loop available, skip async metrics
            logger.debug("No event loop available for async metrics")
    
    def _after_request(self, response: 'Response') -> 'Response':
        """Flask after request handler."""
        if not hasattr(g, 'metrics_start_time'):
            return response
        
        # Calculate metrics
        duration = time.time() - g.metrics_start_time
        status = str(response.status_code)
        method = request.method
        
        # Get response size
        response_size = 0
        if hasattr(response, 'data'):
            response_size = len(response.data)
        elif hasattr(response, 'get_data'):
            try:
                data = response.get_data()
                response_size = len(data)
            except:
                response_size = 0
        
        # Get headers for auth/authz tracking
        headers = {k.lower(): v for k, v in request.headers.items()}
        
        # Record metrics (sync version)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(
                    self._record_request_metrics(
                        method, status, duration, response_size, headers
                    )
                )
            else:
                loop.run_until_complete(
                    self._record_request_metrics(
                        method, status, duration, response_size, headers
                    )
                )
        except RuntimeError:
            logger.debug("No event loop available for async metrics")
        
        return response
    
    def _teardown(self, exception: Exception = None) -> None:
        """Flask teardown handler."""
        # Decrement active requests (sync version)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(
                    self.collector.dec_active_requests(self.handler_name)
                )
            else:
                loop.run_until_complete(
                    self.collector.dec_active_requests(self.handler_name)
                )
        except RuntimeError:
            logger.debug("No event loop available for async metrics")


def create_aiohttp_middleware(collector: MetricsCollector = None,
                            handler_name: str = "aiohttp",
                            track_auth: bool = False,
                            track_authz: bool = False) -> AioHttpMetricsMiddleware:
    """
    Create aiohttp metrics middleware.
    
    Args:
        collector: Metrics collector instance
        handler_name: Handler name for metrics
        track_auth: Track authentication metrics
        track_authz: Track authorization metrics
    
    Returns:
        AioHttpMetricsMiddleware instance
    """
    middleware = AioHttpMetricsMiddleware(
        collector=collector,
        handler_name=handler_name,
        track_auth=track_auth,
        track_authz=track_authz
    )
    return middleware.middleware


def create_fastapi_middleware(collector: MetricsCollector = None,
                            handler_name: str = "fastapi",
                            track_auth: bool = False,
                            track_authz: bool = False) -> FastAPIMetricsMiddleware:
    """
    Create FastAPI metrics middleware.
    
    Args:
        collector: Metrics collector instance
        handler_name: Handler name for metrics
        track_auth: Track authentication metrics
        track_authz: Track authorization metrics
    
    Returns:
        FastAPIMetricsMiddleware class (to be used with app.add_middleware())
    """
    class MiddlewareClass(FastAPIMetricsMiddleware):
        def __init__(self, app):
            super().__init__(
                app,
                collector=collector,
                handler_name=handler_name,
                track_auth=track_auth,
                track_authz=track_authz
            )
    
    return MiddlewareClass


def create_flask_middleware(app: 'Flask' = None,
                          collector: MetricsCollector = None,
                          handler_name: str = "flask",
                          track_auth: bool = False,
                          track_authz: bool = False) -> FlaskMetricsMiddleware:
    """
    Create Flask metrics middleware.
    
    Args:
        app: Flask application instance
        collector: Metrics collector instance
        handler_name: Handler name for metrics
        track_auth: Track authentication metrics
        track_authz: Track authorization metrics
    
    Returns:
        FlaskMetricsMiddleware instance
    """
    return FlaskMetricsMiddleware(
        app=app,
        collector=collector,
        handler_name=handler_name,
        track_auth=track_auth,
        track_authz=track_authz
    )


# Decorators for function-level metrics
def metrics_decorator(collector: MetricsCollector = None,
                     metric_name: str = "function",
                     track_errors: bool = True):
    """
    Decorator to add metrics to any function.
    
    Args:
        collector: Metrics collector instance
        metric_name: Name for the metric
        track_errors: Track function errors
    
    Returns:
        Decorator function
    """
    collector = collector or get_global_collector()
    
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    await collector.record_value(f"{metric_name}_success", 1)
                    return result
                except Exception as e:
                    if track_errors:
                        await collector.record_value(f"{metric_name}_error", 1)
                    raise
                finally:
                    duration = time.time() - start_time
                    await collector.record_value(f"{metric_name}_duration", duration)
            
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    # For sync functions, we can't await, so we schedule the coroutine
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.create_task(
                                collector.record_value(f"{metric_name}_success", 1)
                            )
                    except RuntimeError:
                        pass
                    return result
                except Exception as e:
                    if track_errors:
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                asyncio.create_task(
                                    collector.record_value(f"{metric_name}_error", 1)
                                )
                        except RuntimeError:
                            pass
                    raise
                finally:
                    duration = time.time() - start_time
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.create_task(
                                collector.record_value(f"{metric_name}_duration", duration)
                            )
                    except RuntimeError:
                        pass
            
            return sync_wrapper
    
    return decorator