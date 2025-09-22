"""
Prometheus exporter and HTTP server for GAuth metrics.

This module provides a Prometheus metrics HTTP server and 
export functionality for monitoring GAuth applications.
"""

import asyncio
import logging
from typing import Optional, Callable, Any
from aiohttp import web, ClientSession
import json
from datetime import datetime, timedelta

try:
    from prometheus_client import start_http_server, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from .collector import MetricsCollector, get_global_collector
from ..common.utils import get_current_time


logger = logging.getLogger(__name__)


class PrometheusExporter:
    """Prometheus metrics exporter with HTTP server."""
    
    def __init__(self, 
                 collector: MetricsCollector = None,
                 port: int = 9090,
                 host: str = "0.0.0.0",
                 path: str = "/metrics",
                 enable_health_check: bool = True):
        """
        Initialize Prometheus exporter.
        
        Args:
            collector: Metrics collector instance
            port: HTTP server port
            host: HTTP server host
            path: Metrics endpoint path
            enable_health_check: Enable health check endpoint
        """
        self.collector = collector or get_global_collector()
        self.port = port
        self.host = host
        self.path = path
        self.enable_health_check = enable_health_check
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the Prometheus HTTP server."""
        if self._running:
            logger.warning("Prometheus exporter already running")
            return
        
        if not PROMETHEUS_AVAILABLE:
            logger.error("Cannot start Prometheus exporter: prometheus_client not available")
            raise RuntimeError("prometheus_client package required")
        
        try:
            # Create aiohttp application
            self._app = web.Application()
            
            # Add metrics endpoint
            self._app.router.add_get(self.path, self._metrics_handler)
            
            # Add health check endpoint
            if self.enable_health_check:
                self._app.router.add_get("/health", self._health_handler)
                self._app.router.add_get("/ready", self._ready_handler)
            
            # Add info endpoint
            self._app.router.add_get("/info", self._info_handler)
            
            # Start server
            self._runner = web.AppRunner(self._app)
            await self._runner.setup()
            
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
            
            self._running = True
            logger.info(f"Prometheus exporter started on {self.host}:{self.port}{self.path}")
            
        except Exception as e:
            logger.error(f"Failed to start Prometheus exporter: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the Prometheus HTTP server."""
        if not self._running:
            return
        
        try:
            if self._site:
                await self._site.stop()
            if self._runner:
                await self._runner.cleanup()
            
            self._running = False
            logger.info("Prometheus exporter stopped")
            
        except Exception as e:
            logger.error(f"Error stopping Prometheus exporter: {e}")
    
    async def _metrics_handler(self, request: web.Request) -> web.Response:
        """Handle metrics endpoint requests."""
        try:
            metrics_data = self.collector.export_prometheus_metrics()
            
            return web.Response(
                text=metrics_data,
                content_type=CONTENT_TYPE_LATEST,
                headers={'Cache-Control': 'no-cache'}
            )
            
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return web.Response(
                text=f"# Error generating metrics: {e}\n",
                status=500,
                content_type=CONTENT_TYPE_LATEST
            )
    
    async def _health_handler(self, request: web.Request) -> web.Response:
        """Handle health check requests."""
        try:
            health_data = {
                "status": "healthy",
                "timestamp": get_current_time().isoformat(),
                "metrics_enabled": self.collector.config.enabled,
                "prometheus_enabled": self.collector.config.prometheus_enabled
            }
            
            return web.json_response(health_data)
            
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return web.json_response(
                {"status": "unhealthy", "error": str(e)},
                status=500
            )
    
    async def _ready_handler(self, request: web.Request) -> web.Response:
        """Handle readiness check requests."""
        try:
            # Check if collector is functional
            summary = self.collector.get_metrics_summary()
            
            ready_data = {
                "status": "ready",
                "timestamp": get_current_time().isoformat(),
                "metrics_collector": "operational",
                "metrics_count": summary.get("metrics_count", 0)
            }
            
            return web.json_response(ready_data)
            
        except Exception as e:
            logger.error(f"Readiness check error: {e}")
            return web.json_response(
                {"status": "not_ready", "error": str(e)},
                status=503
            )
    
    async def _info_handler(self, request: web.Request) -> web.Response:
        """Handle info endpoint requests."""
        try:
            summary = self.collector.get_metrics_summary()
            
            info_data = {
                "service": "gauth-metrics",
                "version": "1.0.0",
                "metrics_summary": summary,
                "endpoints": {
                    "metrics": self.path,
                    "health": "/health" if self.enable_health_check else None,
                    "ready": "/ready" if self.enable_health_check else None,
                    "info": "/info"
                },
                "server": {
                    "host": self.host,
                    "port": self.port,
                    "running": self._running
                }
            }
            
            return web.json_response(info_data)
            
        except Exception as e:
            logger.error(f"Info endpoint error: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500
            )
    
    def is_running(self) -> bool:
        """Check if the exporter is running."""
        return self._running


class MetricsPusher:
    """Push metrics to external systems periodically."""
    
    def __init__(self, 
                 collector: MetricsCollector = None,
                 push_interval: float = 30.0,
                 push_gateway_url: Optional[str] = None,
                 webhook_url: Optional[str] = None):
        """
        Initialize metrics pusher.
        
        Args:
            collector: Metrics collector instance
            push_interval: Push interval in seconds
            push_gateway_url: Prometheus push gateway URL
            webhook_url: Webhook URL for custom push
        """
        self.collector = collector or get_global_collector()
        self.push_interval = push_interval
        self.push_gateway_url = push_gateway_url
        self.webhook_url = webhook_url
        self._running = False
        self._push_task: Optional[asyncio.Task] = None
        self._session: Optional[ClientSession] = None
    
    async def start(self) -> None:
        """Start the metrics pusher."""
        if self._running:
            logger.warning("Metrics pusher already running")
            return
        
        try:
            self._session = ClientSession()
            self._running = True
            self._push_task = asyncio.create_task(self._push_loop())
            
            logger.info(f"Metrics pusher started (interval: {self.push_interval}s)")
            
        except Exception as e:
            logger.error(f"Failed to start metrics pusher: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the metrics pusher."""
        if not self._running:
            return
        
        try:
            self._running = False
            
            if self._push_task:
                self._push_task.cancel()
                try:
                    await self._push_task
                except asyncio.CancelledError:
                    pass
            
            if self._session:
                await self._session.close()
            
            logger.info("Metrics pusher stopped")
            
        except Exception as e:
            logger.error(f"Error stopping metrics pusher: {e}")
    
    async def _push_loop(self) -> None:
        """Main push loop."""
        try:
            while self._running:
                await self._push_metrics()
                await asyncio.sleep(self.push_interval)
        except asyncio.CancelledError:
            logger.info("Metrics push loop cancelled")
        except Exception as e:
            logger.error(f"Error in metrics push loop: {e}")
    
    async def _push_metrics(self) -> None:
        """Push metrics to configured destinations."""
        try:
            # Push to Prometheus gateway
            if self.push_gateway_url:
                await self._push_to_prometheus_gateway()
            
            # Push to webhook
            if self.webhook_url:
                await self._push_to_webhook()
                
        except Exception as e:
            logger.error(f"Error pushing metrics: {e}")
    
    async def _push_to_prometheus_gateway(self) -> None:
        """Push metrics to Prometheus push gateway."""
        try:
            await self.collector.push_to_gateway(self.push_gateway_url)
        except Exception as e:
            logger.error(f"Failed to push to Prometheus gateway: {e}")
    
    async def _push_to_webhook(self) -> None:
        """Push metrics to webhook URL."""
        try:
            summary = self.collector.get_metrics_summary()
            
            payload = {
                "timestamp": get_current_time().isoformat(),
                "source": "gauth-metrics",
                "metrics": summary
            }
            
            async with self._session.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            ) as response:
                if response.status == 200:
                    logger.debug("Metrics pushed to webhook successfully")
                else:
                    logger.warning(f"Webhook push failed with status {response.status}")
                    
        except Exception as e:
            logger.error(f"Failed to push to webhook: {e}")


class MetricsMiddleware:
    """HTTP middleware for collecting request metrics."""
    
    def __init__(self, 
                 collector: MetricsCollector = None,
                 handler_name: str = "default"):
        """
        Initialize metrics middleware.
        
        Args:
            collector: Metrics collector instance
            handler_name: Name of the handler for metrics labels
        """
        self.collector = collector or get_global_collector()
        self.handler_name = handler_name
    
    async def __call__(self, request: web.Request, handler: Callable) -> web.Response:
        """Middleware handler for aiohttp."""
        start_time = asyncio.get_event_loop().time()
        
        # Increment active requests
        await self.collector.inc_active_requests(self.handler_name)
        
        try:
            # Process request
            response = await handler(request)
            
            # Record metrics
            duration = asyncio.get_event_loop().time() - start_time
            status = str(response.status)
            method = request.method
            
            # Get response size
            response_size = 0
            if hasattr(response, 'body') and response.body:
                response_size = len(response.body)
            elif hasattr(response, 'text'):
                text = await response.text()
                response_size = len(text.encode('utf-8'))
            
            # Record HTTP metrics
            await self.collector.record_http_request(
                self.handler_name, method, status, duration, response_size
            )
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = asyncio.get_event_loop().time() - start_time
            await self.collector.record_http_request(
                self.handler_name, request.method, "500", duration, 0
            )
            raise
            
        finally:
            # Decrement active requests
            await self.collector.dec_active_requests(self.handler_name)


def create_prometheus_exporter(collector: MetricsCollector = None,
                             port: int = 9090,
                             host: str = "0.0.0.0",
                             path: str = "/metrics") -> PrometheusExporter:
    """
    Create a Prometheus exporter.
    
    Args:
        collector: Metrics collector instance
        port: HTTP server port
        host: HTTP server host
        path: Metrics endpoint path
    
    Returns:
        PrometheusExporter instance
    """
    return PrometheusExporter(collector, port, host, path)


def create_metrics_pusher(collector: MetricsCollector = None,
                         push_interval: float = 30.0,
                         push_gateway_url: Optional[str] = None,
                         webhook_url: Optional[str] = None) -> MetricsPusher:
    """
    Create a metrics pusher.
    
    Args:
        collector: Metrics collector instance
        push_interval: Push interval in seconds
        push_gateway_url: Prometheus push gateway URL
        webhook_url: Webhook URL for custom push
    
    Returns:
        MetricsPusher instance
    """
    return MetricsPusher(collector, push_interval, push_gateway_url, webhook_url)