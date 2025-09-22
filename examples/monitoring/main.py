#!/usr/bin/env python3
"""
Monitoring Examples for GAuth

This example demonstrates monitoring and observability features:
- Metrics collection and reporting
- Health checks
- Performance monitoring
- Audit logging
- Event tracking

Run this example to see how to monitor GAuth applications.
"""

import asyncio
import logging
import time
import random
from datetime import datetime, timedelta

from gauth.monitoring import (
    MetricsCollector, HealthChecker, PerformanceMonitor,
    create_metrics_collector, create_health_checker
)
from gauth.audit import AuditLogger, ConsoleAuditLogger, FileAuditLogger
from gauth.events import EventBus, Event, EventHandler


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DemoService:
    """Demo service for monitoring examples."""
    
    def __init__(self, name: str):
        self.name = name
        self.is_healthy = True
        self.call_count = 0
        self.error_count = 0
    
    async def process_request(self, request_id: str) -> str:
        """Process a request with possible random failures."""
        self.call_count += 1
        
        # Simulate processing time
        processing_time = random.uniform(0.1, 0.5)
        await asyncio.sleep(processing_time)
        
        # Random failures (10% chance)
        if random.random() < 0.1:
            self.error_count += 1
            raise Exception(f"Random failure in {self.name}")
        
        return f"Processed {request_id} in {processing_time:.3f}s"
    
    async def health_check(self) -> bool:
        """Check if service is healthy."""
        # Service is unhealthy if error rate > 20%
        if self.call_count > 0:
            error_rate = self.error_count / self.call_count
            self.is_healthy = error_rate < 0.2
        
        return self.is_healthy


async def demo_metrics_collection():
    """Demonstrate metrics collection."""
    print("\n=== Metrics Collection Demo ===")
    
    # Create metrics collector
    metrics = create_metrics_collector()
    
    # Demo service
    service = DemoService("auth-service")
    
    print("Collecting metrics for 10 requests...")
    
    # Process requests and collect metrics
    for i in range(10):
        request_id = f"req-{i+1}"
        start_time = time.time()
        
        try:
            # Increment request counter
            metrics.increment_counter("requests_total", {"service": service.name})
            
            # Process request
            result = await service.process_request(request_id)
            
            # Record successful request
            metrics.increment_counter("requests_success", {"service": service.name})
            
            # Record response time
            response_time = (time.time() - start_time) * 1000  # ms
            metrics.record_histogram("response_time_ms", response_time, {"service": service.name})
            
            print(f"  ✓ {request_id}: {result}")
            
        except Exception as e:
            # Record failed request
            metrics.increment_counter("requests_failed", {"service": service.name})
            metrics.record_histogram("response_time_ms", 
                                   (time.time() - start_time) * 1000, 
                                   {"service": service.name, "status": "error"})
            
            print(f"  ✗ {request_id}: {e}")
    
    # Get and display metrics
    print("\nCollected Metrics:")
    all_metrics = metrics.get_all_metrics()
    
    for metric_name, metric_data in all_metrics.items():
        print(f"  {metric_name}:")
        if hasattr(metric_data, 'value'):
            print(f"    Value: {metric_data.value}")
        if hasattr(metric_data, 'buckets'):
            print(f"    Count: {len(metric_data.buckets)}")
            if metric_data.buckets:
                avg = sum(metric_data.buckets) / len(metric_data.buckets)
                print(f"    Average: {avg:.2f}")


async def demo_health_checks():
    """Demonstrate health checking."""
    print("\n=== Health Checks Demo ===")
    
    # Create health checker
    health_checker = create_health_checker()
    
    # Demo services
    services = [
        DemoService("auth-service"),
        DemoService("token-service"),
        DemoService("audit-service")
    ]
    
    # Register health checks
    for service in services:
        health_checker.register_check(service.name, service.health_check)
    
    print("Registered health checks for 3 services")
    
    # Simulate some load to potentially affect health
    print("\nSimulating load on services...")
    for i in range(15):
        service = random.choice(services)
        try:
            await service.process_request(f"load-{i+1}")
        except Exception:
            pass  # Ignore errors for health demo
    
    # Perform health checks
    print("\nPerforming health checks:")
    for service in services:
        try:
            is_healthy = await health_checker.check_health(service.name)
            status = "✓ HEALTHY" if is_healthy else "✗ UNHEALTHY"
            error_rate = (service.error_count / service.call_count * 100) if service.call_count > 0 else 0
            print(f"  {service.name}: {status} (calls: {service.call_count}, errors: {service.error_count}, rate: {error_rate:.1f}%)")
        except Exception as e:
            print(f"  {service.name}: ✗ HEALTH CHECK FAILED - {e}")
    
    # Overall health status
    overall_health = await health_checker.check_all_health()
    print(f"\nOverall Health: {'✓ HEALTHY' if overall_health else '✗ UNHEALTHY'}")


async def demo_performance_monitoring():
    """Demonstrate performance monitoring."""
    print("\n=== Performance Monitoring Demo ===")
    
    # Create performance monitor
    perf_monitor = PerformanceMonitor()
    
    service = DemoService("api-service")
    
    print("Monitoring performance for 8 requests...")
    
    # Monitor requests with different performance characteristics
    scenarios = [
        ("fast", 0.05, 0.1),    # Fast requests
        ("normal", 0.1, 0.3),   # Normal requests  
        ("slow", 0.3, 0.8),     # Slow requests
    ]
    
    for i in range(8):
        scenario_name, min_delay, max_delay = random.choice(scenarios)
        request_id = f"perf-{i+1}"
        
        # Start monitoring
        with perf_monitor.monitor_operation(f"request_{scenario_name}"):
            # Simulate variable processing time
            original_delay = service.process_request.__defaults__
            service.response_time = random.uniform(min_delay, max_delay)
            
            try:
                result = await service.process_request(request_id)
                print(f"  ✓ {request_id} ({scenario_name}): {result}")
            except Exception as e:
                print(f"  ✗ {request_id} ({scenario_name}): {e}")
    
    # Get performance statistics
    print("\nPerformance Statistics:")
    stats = perf_monitor.get_statistics()
    
    for operation, operation_stats in stats.items():
        print(f"  {operation}:")
        print(f"    Count: {operation_stats['count']}")
        print(f"    Average: {operation_stats['avg_duration']:.3f}s")
        print(f"    Min: {operation_stats['min_duration']:.3f}s")
        print(f"    Max: {operation_stats['max_duration']:.3f}s")
        
        if operation_stats['count'] > 1:
            print(f"    P95: {operation_stats.get('p95_duration', 'N/A')}")


async def demo_audit_logging():
    """Demonstrate audit logging."""
    print("\n=== Audit Logging Demo ===")
    
    # Create different audit loggers
    console_logger = ConsoleAuditLogger()
    
    print("Demonstrating audit logging for authentication events...")
    
    # Simulate authentication events
    events = [
        ("user_login", {"user_id": "alice", "ip": "192.168.1.100", "user_agent": "Chrome/100.0"}),
        ("token_generated", {"user_id": "alice", "token_type": "JWT", "scope": "read,write"}),
        ("api_access", {"user_id": "alice", "endpoint": "/api/users", "method": "GET"}),
        ("permission_denied", {"user_id": "alice", "resource": "/admin/users", "reason": "insufficient_privileges"}),
        ("user_logout", {"user_id": "alice", "session_duration": 3600}),
        ("failed_login", {"username": "bob", "ip": "192.168.1.200", "reason": "invalid_password"}),
    ]
    
    for event_type, details in events:
        await console_logger.log_event(
            event_type=event_type,
            user_id=details.get("user_id", "unknown"),
            details=details,
            timestamp=datetime.utcnow()
        )
        await asyncio.sleep(0.1)  # Brief delay for demo
    
    print("\nAudit log entries created (check console output above)")


async def demo_event_tracking():
    """Demonstrate event tracking and handling."""
    print("\n=== Event Tracking Demo ===")
    
    # Create event bus
    event_bus = EventBus()
    
    # Event statistics
    event_stats = {"total": 0, "by_type": {}}
    
    # Event handler for statistics
    class StatsHandler(EventHandler):
        async def handle(self, event: Event):
            event_stats["total"] += 1
            event_type = event.event_type
            event_stats["by_type"][event_type] = event_stats["by_type"].get(event_type, 0) + 1
            print(f"  📊 Event tracked: {event_type} (total: {event_stats['total']})")
    
    # Event handler for security alerts
    class SecurityHandler(EventHandler):
        async def handle(self, event: Event):
            if event.event_type in ["failed_login", "permission_denied", "suspicious_activity"]:
                print(f"  🚨 Security Alert: {event.event_type} - {event.data}")
    
    # Register handlers
    stats_handler = StatsHandler()
    security_handler = SecurityHandler()
    
    event_bus.subscribe("*", stats_handler)  # All events
    event_bus.subscribe("security.*", security_handler)  # Security events
    
    print("Event handlers registered for statistics and security monitoring")
    
    # Simulate various events
    events_to_emit = [
        ("user.login", {"user_id": "alice", "success": True}),
        ("user.login", {"user_id": "bob", "success": False}),  
        ("security.failed_login", {"user_id": "bob", "attempt": 1}),
        ("api.request", {"endpoint": "/api/data", "user_id": "alice"}),
        ("security.permission_denied", {"user_id": "alice", "resource": "/admin"}),
        ("user.logout", {"user_id": "alice"}),
        ("security.suspicious_activity", {"ip": "10.0.0.1", "reason": "multiple_failed_logins"}),
        ("system.health_check", {"status": "healthy", "response_time": 45}),
    ]
    
    print("\nEmitting events:")
    for event_type, data in events_to_emit:
        event = Event(
            event_type=event_type,
            data=data,
            timestamp=datetime.utcnow(),
            source="demo"
        )
        
        await event_bus.emit(event)
        await asyncio.sleep(0.2)  # Brief delay for demo
    
    # Show final statistics
    print(f"\nEvent Statistics:")
    print(f"  Total events: {event_stats['total']}")
    print(f"  By type:")
    for event_type, count in event_stats["by_type"].items():
        print(f"    {event_type}: {count}")


async def demo_real_time_dashboard():
    """Simulate a real-time monitoring dashboard."""
    print("\n=== Real-Time Dashboard Simulation ===")
    
    # Create monitoring components
    metrics = create_metrics_collector()
    health_checker = create_health_checker()
    perf_monitor = PerformanceMonitor()
    
    # Demo services
    services = [DemoService(f"service-{i}") for i in range(3)]
    
    # Register health checks
    for service in services:
        health_checker.register_check(service.name, service.health_check)
    
    print("Dashboard running for 10 seconds (simulated real-time data)...")
    
    start_time = time.time()
    update_interval = 2.0  # Update every 2 seconds
    last_update = start_time
    
    while time.time() - start_time < 10:
        current_time = time.time()
        
        # Simulate ongoing requests
        for _ in range(random.randint(1, 3)):
            service = random.choice(services)
            try:
                with perf_monitor.monitor_operation("api_request"):
                    await service.process_request(f"dash-{int(current_time)}")
                metrics.increment_counter("requests_success")
            except Exception:
                metrics.increment_counter("requests_failed")
        
        # Update dashboard every interval
        if current_time - last_update >= update_interval:
            print(f"\n📊 Dashboard Update (t+{int(current_time - start_time)}s):")
            
            # Health status
            overall_health = await health_checker.check_all_health()
            print(f"  System Health: {'🟢 HEALTHY' if overall_health else '🔴 UNHEALTHY'}")
            
            # Request metrics
            all_metrics = metrics.get_all_metrics()
            success_count = all_metrics.get("requests_success", {}).get("value", 0)
            failed_count = all_metrics.get("requests_failed", {}).get("value", 0)
            total_requests = success_count + failed_count
            
            if total_requests > 0:
                success_rate = (success_count / total_requests) * 100
                print(f"  Requests: {total_requests} total, {success_rate:.1f}% success rate")
            
            # Performance stats
            perf_stats = perf_monitor.get_statistics()
            api_stats = perf_stats.get("api_request", {})
            if api_stats:
                print(f"  Performance: {api_stats['avg_duration']:.3f}s avg response time")
            
            last_update = current_time
        
        await asyncio.sleep(0.5)
    
    print("\n📊 Dashboard simulation completed")


async def main():
    """Run all monitoring examples."""
    print("GAuth Monitoring and Observability Examples")
    print("=" * 50)
    
    try:
        await demo_metrics_collection()
        await demo_health_checks()
        await demo_performance_monitoring()
        await demo_audit_logging()
        await demo_event_tracking()
        await demo_real_time_dashboard()
        
        print("\n✓ All monitoring demos completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        logger.exception("Demo failed")
        raise


if __name__ == "__main__":
    asyncio.run(main())