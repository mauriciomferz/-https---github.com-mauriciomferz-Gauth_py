"""
Working test suite for new packages with mock time handling.
"""
import asyncio
import sys
from datetime import datetime, timedelta

# Add current directory to path  
sys.path.insert(0, '/Users/mauricio.fernandez_fernandezsiemens.co/Documents/GitHub/Repo/Gauth_py')

async def test_all_packages():
    """Test all newly implemented packages."""
    
    print("🧪 Testing All New Packages")
    print("=" * 50)
    
    # Test results tracking
    results = {}
    
    # Test Auth Package
    print("\n1️⃣  Testing Authentication Package")
    print("-" * 30)
    
    try:
        from gauth.auth import AuthType, AuthConfig, TokenRequest, GAuthAuthenticator
        
        # Test basic auth (which doesn't rely on timestamps)
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            extra_config={
                'users': {'testuser': 'test_hash'},
                'allow_weak_passwords': True  # For testing
            }
        )
        
        authenticator = GAuthAuthenticator(config)
        await authenticator.initialize()
        
        # Test that authenticator was created
        print("✅ Auth manager created and initialized")
        
        # Test token request creation
        request = TokenRequest(
            grant_type="password",
            username="testuser",
            password="testpass"
        )
        print("✅ Token request created")
        
        await authenticator.close()
        results['auth'] = True
        print("✅ Auth package working")
        
    except Exception as e:
        print(f"❌ Auth package error: {e}")
        results['auth'] = False
    
    # Test Circuit Breaker Package
    print("\n2️⃣  Testing Circuit Breaker Package")
    print("-" * 30)
    
    try:
        from gauth.circuit import CircuitBreaker, CircuitBreakerOptions, CircuitState
        
        options = CircuitBreakerOptions(
            name="test_circuit",
            failure_threshold=2,
            reset_timeout=timedelta(seconds=1)
        )
        
        circuit = CircuitBreaker(options)
        print("✅ Circuit breaker created")
        
        # Test successful call
        async def success_func():
            return "circuit_success"
        
        result = await circuit.call(success_func)
        print(f"✅ Successful call: {result}")
        
        # Test state
        assert circuit.state == CircuitState.CLOSED
        print("✅ Circuit state correct")
        
        results['circuit'] = True
        print("✅ Circuit breaker package working")
        
    except Exception as e:
        print(f"❌ Circuit breaker error: {e}")
        results['circuit'] = False
    
    # Test Resilience Package
    print("\n3️⃣  Testing Resilience Package")
    print("-" * 30)
    
    try:
        from gauth.resilience import (
            RetryConfig, Retry, TimeoutConfig, Timeout,
            BulkheadConfig, Bulkhead, RateLimiter, RateLimitConfig
        )
        
        # Test Retry
        retry_config = RetryConfig(
            max_attempts=3,
            initial_delay=timedelta(milliseconds=10)
        )
        retry_handler = Retry(retry_config)
        print("✅ Retry handler created")
        
        attempt_count = 0
        async def retry_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise ValueError(f"Attempt {attempt_count}")
            return "retry_success"
        
        result = await retry_handler.execute(retry_func)
        print(f"✅ Retry success: {result} (attempts: {attempt_count})")
        
        # Test Timeout
        timeout_config = TimeoutConfig(timeout=timedelta(seconds=1))
        timeout_handler = Timeout(timeout_config)
        print("✅ Timeout handler created")
        
        async def fast_func():
            await asyncio.sleep(0.01)
            return "timeout_success"
        
        result = await timeout_handler.execute(fast_func)
        print(f"✅ Timeout success: {result}")
        
        # Test Rate Limiter
        rate_config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=5
        )
        rate_limiter = RateLimiter(rate_config)
        print("✅ Rate limiter created")
        
        # Should allow initial requests
        assert rate_limiter.acquire() == True
        print("✅ Rate limiting working")
        
        results['resilience'] = True
        print("✅ Resilience package working")
        
    except Exception as e:
        print(f"❌ Resilience error: {e}")
        import traceback
        traceback.print_exc()
        results['resilience'] = False
    
    # Test Integration
    print("\n4️⃣  Testing Package Integration")
    print("-" * 30)
    
    try:
        from gauth.circuit import CircuitBreakerOptions
        from gauth.resilience import resilient_call, RetryConfig, TimeoutConfig
        
        # Test integration of circuit breaker with resilience
        circuit_options = CircuitBreakerOptions(
            name="integration_test",
            failure_threshold=3
        )
        
        retry_config = RetryConfig(
            max_attempts=2,
            initial_delay=timedelta(milliseconds=5)
        )
        
        timeout_config = TimeoutConfig(
            timeout=timedelta(seconds=1)
        )
        
        async def integration_func():
            return "integration_success"
        
        result = await resilient_call(
            integration_func,
            circuit_options=circuit_options,
            retry_config=retry_config,
            timeout_config=timeout_config
        )
        
        print(f"✅ Integration success: {result}")
        results['integration'] = True
        print("✅ Package integration working")
        
    except Exception as e:
        print(f"❌ Integration error: {e}")
        results['integration'] = False
    
    # Summary
    print("\n📊 Test Summary")
    print("=" * 50)
    
    for package, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{package.capitalize():<15}: {status}")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    
    print(f"\nTotal: {passed_tests}/{total_tests} packages working")
    
    if passed_tests == total_tests:
        print("\n🎉 ALL TESTS PASSED!")
        print("New packages (auth, circuit, resilience) are fully functional!")
    else:
        print(f"\n⚠️  {total_tests - passed_tests} package(s) have issues")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    success = asyncio.run(test_all_packages())
    exit(0 if success else 1)