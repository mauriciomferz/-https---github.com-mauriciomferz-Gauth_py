"""
Simple working test for auth packages.
"""
import asyncio
import sys
from datetime import timedelta

# Add current directory to path
sys.path.insert(0, '/Users/mauricio.fernandez_fernandezsiemens.co/Documents/GitHub/Repo/Gauth_py')

from gauth.auth import AuthType, AuthConfig, TokenRequest, GAuthAuthenticator

async def test_working_auth():
    """Test authentication with longer expiry."""
    print("Testing auth with longer expiry...")
    
    # Create config with longer expiry
    config = AuthConfig(
        auth_type=AuthType.JWT,
        access_token_expiry=timedelta(minutes=60),  # 1 hour
        extra_config={'secret_key': 'test_secret'}
    )
    
    authenticator = GAuthAuthenticator(config)
    
    try:
        await authenticator.initialize()
        print("✓ Authenticator initialized")
        
        # Generate token
        request = TokenRequest(
            grant_type="client_credentials",
            subject="test_user"
        )
        
        response = await authenticator.generate_token(request)
        print(f"✓ Token generated: {response.access_token[:50]}...")
        
        # Validate token immediately (should work)
        validation_result = await authenticator.validate_token(response.access_token)
        print(f"✓ Token validation: {validation_result.valid}")
        
        if validation_result.valid:
            print(f"✓ Subject: {validation_result.token_data.subject}")
        else:
            print(f"✗ Validation error: {validation_result.error_message}")
        
        await authenticator.close()
        
        return validation_result.valid
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

# Simple circuit breaker test
async def test_circuit_breaker():
    """Test circuit breaker functionality."""
    print("\nTesting circuit breaker...")
    
    from gauth.circuit import CircuitBreaker, CircuitBreakerOptions
    from datetime import timedelta
    
    options = CircuitBreakerOptions(
        name="test_circuit",
        failure_threshold=2,
        reset_timeout=timedelta(seconds=1)
    )
    
    circuit = CircuitBreaker(options)
    
    async def success_func():
        return "success"
    
    try:
        result = await circuit.call(success_func)
        print(f"✓ Circuit breaker call: {result}")
        return True
    except Exception as e:
        print(f"✗ Circuit breaker error: {e}")
        return False

# Simple resilience test  
async def test_resilience():
    """Test resilience patterns."""
    print("\nTesting resilience patterns...")
    
    from gauth.resilience import RetryConfig, Retry
    from datetime import timedelta
    
    config = RetryConfig(
        max_attempts=2,
        initial_delay=timedelta(milliseconds=10)
    )
    
    retry_handler = Retry(config)
    
    attempt_count = 0
    
    async def test_func():
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            raise ValueError("First attempt fails")
        return "retry success"
    
    try:
        result = await retry_handler.execute(test_func)
        print(f"✓ Retry pattern: {result} (attempts: {attempt_count})")
        return True
    except Exception as e:
        print(f"✗ Retry error: {e}")
        return False

async def main():
    """Run all tests."""
    print("Running comprehensive tests for new packages...\n")
    
    auth_result = await test_working_auth()
    circuit_result = await test_circuit_breaker()
    resilience_result = await test_resilience()
    
    print(f"\n🔍 Test Results:")
    print(f"  Auth Package: {'✅' if auth_result else '❌'}")
    print(f"  Circuit Breaker: {'✅' if circuit_result else '❌'}")
    print(f"  Resilience: {'✅' if resilience_result else '❌'}")
    
    if all([auth_result, circuit_result, resilience_result]):
        print("\n🎉 All tests passed! New packages are working correctly.")
    else:
        print("\n⚠️  Some tests failed. Check implementation.")

if __name__ == "__main__":
    asyncio.run(main())