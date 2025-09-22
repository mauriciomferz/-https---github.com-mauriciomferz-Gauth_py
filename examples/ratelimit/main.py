#!/usr/bin/env python3
"""
Rate Limiting Examples for GAuth

This example demonstrates various rate limiting algorithms:
- Token Bucket Rate Limiting
- Sliding Window Rate Limiting  
- Fixed Window Rate Limiting
- Adaptive Rate Limiting

Run this example to see how different rate limiting strategies work.
"""

import asyncio
import logging
import time
from typing import List

from gauth.ratelimit import (
    TokenBucketRateLimiter,
    AdaptiveRateLimiter, AdaptiveConfig,
    ClientAdaptiveRateLimiter,
    PreciseSlidingWindowRateLimiter, SlidingWindowConfig,
    PreciseFixedWindowRateLimiter,
    create_adaptive_limiter,
    create_sliding_window_limiter,
    create_fixed_window_limiter
)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def demo_token_bucket():
    """Demonstrate token bucket rate limiting."""
    print("\n=== Token Bucket Rate Limiting Demo ===")
    
    # Create token bucket limiter: 5 requests per 10 seconds, burst of 10
    limiter = TokenBucketRateLimiter(
        max_requests=5,
        time_window=10,
        burst_limit=10
    )
    
    print("Token Bucket: 5 requests/10s, burst=10")
    
    # Test burst capability
    print("\nTesting burst capability:")
    for i in range(12):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        print(f"  Request {i+1}: {status}")
        
        if i == 7:  # Brief pause mid-burst
            print("    [brief pause]")
            await asyncio.sleep(0.1)
    
    # Wait and test refill
    print("\nWaiting 5 seconds for token refill...")
    await asyncio.sleep(5)
    
    print("Testing after refill:")
    for i in range(3):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        print(f"  Request {i+1}: {status}")


async def demo_sliding_window():
    """Demonstrate sliding window rate limiting."""
    print("\n=== Sliding Window Rate Limiting Demo ===")
    
    # Create sliding window limiter: 3 requests per 5 seconds
    config = SlidingWindowConfig(limit=3, window_seconds=5.0)
    limiter = create_sliding_window_limiter(config)
    
    print("Sliding Window: 3 requests/5s")
    
    # Test normal operation
    print("\nTesting normal operation:")
    for i in range(5):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        usage = limiter.get_window_usage("client1")
        print(f"  Request {i+1}: {status} (count: {usage['current_count']}/{usage['limit']})")
        
        if i == 2:  # Wait for window to partially slide
            print("    [waiting 3 seconds]")
            await asyncio.sleep(3)
    
    # Test window sliding
    print("\nTesting window sliding after 6 seconds...")
    await asyncio.sleep(3)  # Total 6 seconds waited
    
    for i in range(3):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        usage = limiter.get_window_usage("client1")
        print(f"  Request {i+1}: {status} (count: {usage['current_count']}/{usage['limit']})")


async def demo_fixed_window():
    """Demonstrate fixed window rate limiting."""
    print("\n=== Fixed Window Rate Limiting Demo ===")
    
    # Create fixed window limiter: 4 requests per 3 seconds
    config = SlidingWindowConfig(limit=4, window_seconds=3.0)
    limiter = create_fixed_window_limiter(config)
    
    print("Fixed Window: 4 requests/3s")
    
    # Test within single window
    print("\nTesting within single window:")
    for i in range(6):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        usage = limiter.get_window_usage("client1")
        print(f"  Request {i+1}: {status} (count: {usage['current_count']}/{usage['limit']})")
        await asyncio.sleep(0.2)
    
    # Wait for window reset
    print("\nWaiting for window reset...")
    await asyncio.sleep(3.5)
    
    print("Testing after window reset:")
    for i in range(3):
        allowed = await limiter.allow("client1")
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        usage = limiter.get_window_usage("client1")
        print(f"  Request {i+1}: {status} (count: {usage['current_count']}/{usage['limit']})")


async def demo_adaptive_limiting():
    """Demonstrate adaptive rate limiting."""
    print("\n=== Adaptive Rate Limiting Demo ===")
    
    # Create adaptive limiter: starts at 5, can adapt between 2-20
    config = AdaptiveConfig(
        initial_limit=5,
        min_limit=2,
        max_limit=20,
        window_seconds=2.0,
        scale_up_factor=1.5,
        scale_down_factor=0.7,
        adaptation_threshold=0.8
    )
    limiter = create_adaptive_limiter(config)
    
    print("Adaptive Limiter: 5 initial, range 2-20, window=2s")
    
    # Simulate low usage to trigger scale-up
    print("\nSimulating low usage (should scale up):")
    for window in range(3):
        print(f"  Window {window+1}:")
        stats = limiter.get_stats()
        print(f"    Current limit: {stats['current_limit']}")
        
        # Use only 40% of capacity
        requests_to_make = max(1, int(stats['current_limit'] * 0.4))
        for i in range(requests_to_make):
            allowed = await limiter.allow("client1")
            status = "✓" if allowed else "✗"
            print(f"      Request {i+1}: {status}")
        
        await asyncio.sleep(2.1)  # Wait for window reset and adaptation
    
    # Simulate high usage to trigger scale-down
    print("\nSimulating high usage (should scale down):")
    for window in range(3):
        print(f"  Window {window+1}:")
        stats = limiter.get_stats()
        print(f"    Current limit: {stats['current_limit']}")
        
        # Try to exceed capacity
        for i in range(stats['current_limit'] + 2):
            allowed = await limiter.allow("client1")
            status = "✓" if allowed else "✗"
            print(f"      Request {i+1}: {status}")
        
        await asyncio.sleep(2.1)  # Wait for window reset and adaptation


async def demo_client_adaptive():
    """Demonstrate per-client adaptive rate limiting."""
    print("\n=== Client Adaptive Rate Limiting Demo ===")
    
    config = AdaptiveConfig(
        initial_limit=3,
        min_limit=1,
        max_limit=10,
        window_seconds=2.0
    )
    limiter = ClientAdaptiveRateLimiter(config)
    
    print("Client Adaptive: 3 initial per client, range 1-10")
    
    clients = ["alice", "bob", "charlie"]
    
    # Test multiple clients
    print("\nTesting multiple clients:")
    for round_num in range(2):
        print(f"  Round {round_num + 1}:")
        
        for client in clients:
            print(f"    Client {client}:")
            stats = limiter.get_client_stats(client)
            if stats:
                print(f"      Current limit: {stats['current_limit']}")
            
            # Each client makes different number of requests
            client_requests = 2 if client == "alice" else 1 if client == "bob" else 4
            
            for i in range(client_requests):
                allowed = await limiter.allow(client)
                status = "✓" if allowed else "✗"
                print(f"        Request {i+1}: {status}")
        
        await asyncio.sleep(2.1)  # Wait for window reset
    
    # Show final stats
    print("\nFinal client statistics:")
    all_stats = limiter.get_all_stats()
    for client, stats in all_stats.items():
        print(f"  {client}: limit={stats['current_limit']}, usage_rate={stats.get('usage_rate', 0):.2f}")


async def simulate_realistic_traffic():
    """Simulate realistic traffic patterns."""
    print("\n=== Realistic Traffic Simulation ===")
    
    # Create a sliding window limiter for realistic testing
    config = SlidingWindowConfig(limit=10, window_seconds=5.0)
    limiter = create_sliding_window_limiter(config)
    
    print("Simulating realistic API traffic: 10 requests/5s")
    
    # Simulate burst followed by normal traffic
    traffic_patterns = [
        ("Burst traffic", [0.1] * 15),  # 15 requests in 1.5 seconds
        ("Normal traffic", [0.5] * 8),  # 8 requests over 4 seconds  
        ("Slow traffic", [1.0] * 5),    # 5 requests over 5 seconds
    ]
    
    for pattern_name, delays in traffic_patterns:
        print(f"\n{pattern_name}:")
        allowed_count = 0
        denied_count = 0
        
        for i, delay in enumerate(delays):
            allowed = await limiter.allow("api_client")
            if allowed:
                allowed_count += 1
                print(f"  Request {i+1}: ✓ ALLOWED")
            else:
                denied_count += 1
                print(f"  Request {i+1}: ✗ DENIED")
            
            usage = limiter.get_window_usage("api_client")
            print(f"    Window usage: {usage['current_count']}/{usage['limit']}")
            
            await asyncio.sleep(delay)
        
        print(f"  Result: {allowed_count} allowed, {denied_count} denied")
        
        # Brief pause between patterns
        await asyncio.sleep(2)


async def main():
    """Run all rate limiting examples."""
    print("GAuth Rate Limiting Examples")
    print("=" * 50)
    
    try:
        await demo_token_bucket()
        await demo_sliding_window()
        await demo_fixed_window()
        await demo_adaptive_limiting()
        await demo_client_adaptive()
        await simulate_realistic_traffic()
        
        print("\n✓ All rate limiting demos completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        logger.exception("Demo failed")
        raise


if __name__ == "__main__":
    asyncio.run(main())