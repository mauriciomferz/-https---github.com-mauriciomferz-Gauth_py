#!/usr/bin/env python3
"""
Resilience Examples for GAuth

This example demonstrates resilience patterns:
- Circuit Breaker pattern
- Retry with exponential backoff
- Timeout handling
- Graceful degradation

Run this example to see how GAuth handles failures gracefully.
"""

import asyncio
import logging
import random
import time
from typing import Optional

from gauth.circuit import CircuitBreaker, CircuitConfig, CircuitState
from gauth.resilience import (
    RetryPolicy, ExponentialBackoff, LinearBackoff,
    TimeoutPolicy, with_retry, with_timeout, with_circuit_breaker
)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UnreliableService:
    """Simulates an unreliable external service."""
    
    def __init__(self, failure_rate: float = 0.3, response_time: float = 0.1):
        self.failure_rate = failure_rate
        self.response_time = response_time
        self.call_count = 0
    
    async def call(self, data: str = "test") -> str:
        """Simulate a service call that may fail."""
        self.call_count += 1
        
        # Simulate network delay
        await asyncio.sleep(self.response_time)
        
        # Randomly fail based on failure rate
        if random.random() < self.failure_rate:
            raise Exception(f"Service failure on call {self.call_count}")
        
        return f"Success: {data} (call #{self.call_count})"


class SlowService:
    """Simulates a slow external service."""
    
    def __init__(self, delay: float = 2.0):
        self.delay = delay
        self.call_count = 0
    
    async def call(self, data: str = "test") -> str:
        """Simulate a slow service call."""
        self.call_count += 1
        await asyncio.sleep(self.delay)
        return f"Slow response: {data} (call #{self.call_count})"


async def demo_circuit_breaker():
    """Demonstrate circuit breaker pattern."""
    print("\n=== Circuit Breaker Demo ===")
    
    # Create circuit breaker: fails after 3 failures, recovers after 2 seconds
    config = CircuitConfig(
        failure_threshold=3,
        recovery_timeout_seconds=2.0,
        success_threshold=2
    )
    circuit = CircuitBreaker("demo-service", config)
    
    # Create unreliable service
    service = UnreliableService(failure_rate=0.8)  # 80% failure rate
    
    print("Circuit Breaker: 3 failures → OPEN, 2s timeout, 2 successes → CLOSED")
    print("Service failure rate: 80%")
    
    # Test circuit breaker progression
    for i in range(12):
        try:
            async with circuit:
                result = await service.call(f"request-{i+1}")
                print(f"  Call {i+1}: ✓ {result}")
                
        except Exception as e:
            state = circuit.get_state()
            print(f"  Call {i+1}: ✗ Failed - {e} (Circuit: {state.value})")
        
        # Show circuit state
        stats = circuit.get_stats()
        print(f"    Circuit stats: failures={stats.failure_count}, state={stats.state.value}")
        
        # Brief delay between calls
        await asyncio.sleep(0.3)
        
        # After call 8, wait for recovery timeout
        if i == 7:
            print("    [Waiting for circuit recovery timeout...]")
            await asyncio.sleep(2.5)


async def demo_retry_with_backoff():
    """Demonstrate retry with exponential backoff."""
    print("\n=== Retry with Exponential Backoff Demo ===")
    
    # Create retry policy with exponential backoff
    backoff = ExponentialBackoff(
        initial_delay=0.1,
        max_delay=2.0,
        multiplier=2.0,
        jitter=True
    )
    
    retry_policy = RetryPolicy(
        max_attempts=5,
        backoff=backoff,
        exceptions=(Exception,)
    )
    
    service = UnreliableService(failure_rate=0.6)  # 60% failure rate
    
    print("Retry Policy: 5 attempts, exponential backoff (0.1s → 2s)")
    print("Service failure rate: 60%")
    
    @with_retry(retry_policy)
    async def reliable_call(data: str) -> str:
        return await service.call(data)
    
    # Test retries
    for i in range(3):
        print(f"\nAttempting call {i+1}:")
        try:
            start_time = time.time()
            result = await reliable_call(f"retry-test-{i+1}")
            duration = time.time() - start_time
            print(f"  ✓ Success after {duration:.2f}s: {result}")
        except Exception as e:
            duration = time.time() - start_time
            print(f"  ✗ Failed after {duration:.2f}s: {e}")


async def demo_timeout_handling():
    """Demonstrate timeout handling."""
    print("\n=== Timeout Handling Demo ===")
    
    # Create timeout policy
    timeout_policy = TimeoutPolicy(timeout_seconds=1.0)
    
    print("Timeout Policy: 1 second timeout")
    
    # Test with slow service
    slow_service = SlowService(delay=2.0)  # 2 second delay
    fast_service = SlowService(delay=0.5)  # 0.5 second delay
    
    @with_timeout(timeout_policy)
    async def timed_call(service, data: str) -> str:
        return await service.call(data)
    
    # Test timeout scenarios
    test_cases = [
        ("Fast service (0.5s)", fast_service),
        ("Slow service (2.0s)", slow_service),
    ]
    
    for name, service in test_cases:
        print(f"\nTesting {name}:")
        try:
            start_time = time.time()
            result = await timed_call(service, "timeout-test")
            duration = time.time() - start_time
            print(f"  ✓ Success in {duration:.2f}s: {result}")
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            print(f"  ✗ Timeout after {duration:.2f}s")
        except Exception as e:
            duration = time.time() - start_time
            print(f"  ✗ Error after {duration:.2f}s: {e}")


async def demo_combined_patterns():
    """Demonstrate combining multiple resilience patterns."""
    print("\n=== Combined Resilience Patterns Demo ===")
    
    # Create combined policies
    circuit_config = CircuitConfig(
        failure_threshold=2,
        recovery_timeout_seconds=1.0,
        success_threshold=1
    )
    
    retry_policy = RetryPolicy(
        max_attempts=3,
        backoff=LinearBackoff(delay=0.2),
        exceptions=(Exception,)
    )
    
    timeout_policy = TimeoutPolicy(timeout_seconds=0.5)
    
    print("Combined: Circuit Breaker + Retry + Timeout")
    print("- Circuit: 2 failures → OPEN, 1s recovery")
    print("- Retry: 3 attempts, 0.2s linear backoff")  
    print("- Timeout: 0.5s timeout")
    
    # Create unreliable and slow service
    service = UnreliableService(failure_rate=0.5)
    service.response_time = 0.3  # Sometimes slow
    
    circuit = CircuitBreaker("combined-demo", circuit_config)
    
    @with_retry(retry_policy)
    @with_timeout(timeout_policy)
    async def resilient_call(data: str) -> str:
        async with circuit:
            return await service.call(data)
    
    # Test combined patterns
    for i in range(8):
        print(f"\nCall {i+1}:")
        try:
            start_time = time.time()
            result = await resilient_call(f"combined-{i+1}")
            duration = time.time() - start_time
            print(f"  ✓ Success in {duration:.2f}s: {result}")
        except Exception as e:
            duration = time.time() - start_time
            print(f"  ✗ Failed after {duration:.2f}s: {e}")
        
        # Show circuit state
        stats = circuit.get_stats()
        print(f"    Circuit: {stats.state.value} (failures: {stats.failure_count})")
        
        await asyncio.sleep(0.1)


async def demo_graceful_degradation():
    """Demonstrate graceful degradation patterns."""
    print("\n=== Graceful Degradation Demo ===")
    
    # Create services
    primary_service = UnreliableService(failure_rate=0.7)  # Often fails
    cache_service = UnreliableService(failure_rate=0.1)    # Reliable cache
    
    print("Graceful Degradation: Primary service → Cache → Default response")
    
    async def get_data_with_fallback(key: str) -> str:
        """Try primary service, fallback to cache, then default."""
        
        # Try primary service
        try:
            result = await primary_service.call(f"primary:{key}")
            print(f"  ✓ Primary service: {result}")
            return result
        except Exception as e:
            print(f"  ✗ Primary service failed: {e}")
        
        # Fallback to cache
        try:
            result = await cache_service.call(f"cache:{key}")
            print(f"  ✓ Cache service: {result}")
            return result
        except Exception as e:
            print(f"  ✗ Cache service failed: {e}")
        
        # Default response
        default_result = f"Default response for {key}"
        print(f"  ℹ Default response: {default_result}")
        return default_result
    
    # Test graceful degradation
    for i in range(5):
        print(f"\nRequest {i+1}:")
        result = await get_data_with_fallback(f"item-{i+1}")
        print(f"  Final result: {result}")


async def main():
    """Run all resilience examples."""
    print("GAuth Resilience Patterns Examples")
    print("=" * 50)
    
    try:
        await demo_circuit_breaker()
        await demo_retry_with_backoff()
        await demo_timeout_handling()
        await demo_combined_patterns()
        await demo_graceful_degradation()
        
        print("\n✓ All resilience demos completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        logger.exception("Demo failed")
        raise


if __name__ == "__main__":
    asyncio.run(main())