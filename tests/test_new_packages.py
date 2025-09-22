"""
Comprehensive tests for newly implemented packages: auth, circuit, resilience.
"""

import asyncio
import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Auth package imports
from gauth.auth import (
    AuthType, AuthConfig, TokenRequest, TokenResponse, 
    GAut        # Test decorator-style retry usage using the Retry class
        config = RetryConfig(
            max_attempts=3,
            initial_delay=timedelta(milliseconds=1)
        )
        
        attempt_count = 0
        retry_handler = Retry(config)
        
        async def decorated_retry_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise ValueError(f"Attempt {attempt_count}")
            return "decorated success"
        
        result = await retry_handler.execute(decorated_retry_func)
        assert result == "decorated success"
        assert attempt_count == 2Manager, PasetoManager, OAuth2Manager, BasicAuthManager,
    AuthError, TokenError, ValidationError
)

# Circuit package imports  
from gauth.circuit import (
    CircuitBreaker, CircuitBreakerOptions, CircuitState,
    CircuitBreakerOpenError, circuit_breaker, with_circuit_breaker
)

# Resilience package imports
from gauth.resilience import (
    RetryConfig, Retry, TimeoutConfig, Timeout, BulkheadConfig, Bulkhead,
    RateLimitConfig, RateLimiter, resilient_call,
    BulkheadFullError, RateLimitExceededError
)


class TestAuthPackage:
    """Test authentication package functionality."""
    
    def test_auth_config_creation(self):
        """Test creating auth configuration."""
        config = AuthConfig(
            auth_type=AuthType.JWT,
            client_id="test_client",
            scopes=["read", "write"]
        )
        
        assert config.auth_type == AuthType.JWT
        assert config.client_id == "test_client"
        assert config.scopes == ["read", "write"]
    
    def test_token_request_creation(self):
        """Test creating token request."""
        request = TokenRequest(
            grant_type="client_credentials",
            client_id="test_client",
            scope="read write"
        )
        
        assert request.grant_type == "client_credentials"
        assert request.client_id == "test_client"
        assert request.scope == "read write"
    
    @pytest.mark.asyncio
    async def test_jwt_manager(self):
        """Test JWT manager functionality."""
        config = AuthConfig(
            auth_type=AuthType.JWT,
            extra_config={
                'secret_key': 'test_secret',
                'algorithm': 'HS256'
            }
        )
        
        manager = JWTManager(config)
        await manager.initialize()
        
        # Test token generation
        request = TokenRequest(
            grant_type="client_credentials",
            subject="test_user",
            scope="read"
        )
        
        response = await manager.generate_token(request)
        assert response.access_token is not None
        assert response.token_type == "Bearer"
        
        # Test token validation
        validation_result = await manager.validate_token(response.access_token)
        assert validation_result.valid is True
        assert validation_result.token_data.subject == "test_user"
        
        await manager.close()
    
    @pytest.mark.asyncio
    async def test_basic_auth_manager(self):
        """Test basic auth manager functionality."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            extra_config={
                'users': {'testuser': 'hashedpassword'}
            }
        )
        
        manager = BasicAuthManager(config)
        await manager.initialize()
        
        # Test credential validation (this will fail with hash mismatch, which is expected)
        credentials = {'username': 'testuser', 'password': 'wrongpassword'}
        is_valid = await manager.validate_credentials(credentials)
        assert is_valid is False  # Wrong password
        
        await manager.close()
    
    @pytest.mark.asyncio
    async def test_gauth_authenticator(self):
        """Test main GAuth authenticator."""
        config = AuthConfig(
            auth_type=AuthType.JWT,
            extra_config={'secret_key': 'test_secret'}
        )
        
        authenticator = GAuthAuthenticator(config)
        await authenticator.initialize()
        
        # Test token generation
        request = TokenRequest(
            grant_type="client_credentials",
            subject="test_user"
        )
        
        response = await authenticator.generate_token(request)
        assert response.access_token is not None
        
        # Test token validation
        validation_result = await authenticator.validate_token(response.access_token)
        assert validation_result.valid is True
        
        await authenticator.close()


class TestCircuitPackage:
    """Test circuit breaker package functionality."""
    
    def test_circuit_breaker_creation(self):
        """Test creating circuit breaker."""
        options = CircuitBreakerOptions(
            name="test_circuit",
            failure_threshold=3,
            reset_timeout=timedelta(seconds=5)
        )
        
        circuit = CircuitBreaker(options)
        assert circuit.name == "test_circuit"
        assert circuit.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_success(self):
        """Test circuit breaker with successful calls."""
        options = CircuitBreakerOptions(
            name="test_circuit",
            failure_threshold=3
        )
        
        circuit = CircuitBreaker(options)
        
        async def successful_func():
            return "success"
        
        result = await circuit.call(successful_func)
        assert result == "success"
        assert circuit.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_failure(self):
        """Test circuit breaker with failures."""
        options = CircuitBreakerOptions(
            name="test_circuit",
            failure_threshold=2,
            reset_timeout=timedelta(seconds=1)
        )
        
        circuit = CircuitBreaker(options)
        
        async def failing_func():
            raise ValueError("Test failure")
        
        # First failure
        with pytest.raises(ValueError):
            await circuit.call(failing_func)
        assert circuit.state == CircuitState.CLOSED
        
        # Second failure should open circuit
        with pytest.raises(ValueError):
            await circuit.call(failing_func)
        assert circuit.state == CircuitState.OPEN
        
        # Next call should be blocked
        with pytest.raises(CircuitBreakerOpenError):
            await circuit.call(failing_func)
    
    @pytest.mark.asyncio  
    async def test_circuit_breaker_decorator(self):
        """Test circuit breaker decorator."""
        options = CircuitBreakerOptions(
            name="decorated_circuit",
            failure_threshold=2
        )
        
        @circuit_breaker(options)
        async def decorated_func(should_fail=False):
            if should_fail:
                raise ValueError("Decorator test failure")
            return "decorator success"
        
        # Successful call
        result = await decorated_func(should_fail=False)
        assert result == "decorator success"
        
        # Failing calls
        with pytest.raises(ValueError):
            await decorated_func(should_fail=True)
        
        with pytest.raises(ValueError):
            await decorated_func(should_fail=True)


class TestResiliencePackage:
    """Test resilience package functionality."""
    
    @pytest.mark.asyncio
    async def test_retry_pattern(self):
        """Test retry pattern."""
        config = RetryConfig(
            max_attempts=3,
            initial_delay=timedelta(milliseconds=10)
        )
        
        retry_handler = Retry(config)
        
        attempt_count = 0
        
        async def flaky_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise ValueError(f"Attempt {attempt_count} failed")
            return "success"
        
        result = await retry_handler.execute(flaky_func)
        assert result == "success"
        assert attempt_count == 3
    
    @pytest.mark.asyncio
    async def test_timeout_pattern(self):
        """Test timeout pattern."""
        config = TimeoutConfig(timeout=timedelta(milliseconds=100))
        timeout_handler = Timeout(config)
        
        async def fast_func():
            await asyncio.sleep(0.01)  # 10ms
            return "fast"
        
        async def slow_func():
            await asyncio.sleep(0.2)  # 200ms
            return "slow"
        
        # Fast function should succeed
        result = await timeout_handler.execute(fast_func)
        assert result == "fast"
        
        # Slow function should timeout
        with pytest.raises(TimeoutError):
            await timeout_handler.execute(slow_func)
    
    @pytest.mark.asyncio
    async def test_bulkhead_pattern(self):
        """Test bulkhead pattern."""
        config = BulkheadConfig(
            name="test_bulkhead",
            max_concurrent=2,
            timeout=timedelta(milliseconds=100)
        )
        
        bulkhead = Bulkhead(config)
        
        active_count = 0
        max_concurrent = 0
        
        async def tracked_func():
            nonlocal active_count, max_concurrent
            active_count += 1
            max_concurrent = max(max_concurrent, active_count)
            await asyncio.sleep(0.05)  # 50ms
            active_count -= 1
            return "done"
        
        # Run multiple concurrent tasks
        tasks = [bulkhead.execute(tracked_func) for _ in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check that bulkhead limited concurrency
        assert max_concurrent <= 2
        
        # Some requests should succeed
        successful_results = [r for r in results if r == "done"]
        assert len(successful_results) >= 2
    
    def test_rate_limiter(self):
        """Test rate limiter."""
        config = RateLimitConfig(
            requests_per_second=2.0,
            burst_size=2
        )
        
        rate_limiter = RateLimiter(config)
        
        # First two requests should succeed immediately
        assert rate_limiter.acquire() is True
        assert rate_limiter.acquire() is True
        
        # Third request should fail (burst exhausted)
        assert rate_limiter.acquire() is False
        
        # After some time, should be able to acquire again
        time.sleep(0.6)  # Wait for token replenishment
        assert rate_limiter.acquire() is True
    
    @pytest.mark.asyncio
    async def test_retry_decorator(self):
        """Test retry decorator."""
        config = RetryConfig(
            max_attempts=3,
            initial_delay=timedelta(milliseconds=1)
        )
        
        attempt_count = 0
        
        @retry(config)
        async def decorated_retry_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise ValueError(f"Attempt {attempt_count}")
            return "decorated success"
        
        result = await decorated_retry_func()
        assert result == "decorated success"
        assert attempt_count == 2
    
    @pytest.mark.asyncio
    async def test_resilient_call(self):
        """Test resilient call with multiple patterns."""
        from gauth.circuit import CircuitBreakerOptions
        
        circuit_options = CircuitBreakerOptions(
            name="resilient_test",
            failure_threshold=3
        )
        
        retry_config = RetryConfig(
            max_attempts=2,
            initial_delay=timedelta(milliseconds=1)
        )
        
        timeout_config = TimeoutConfig(
            timeout=timedelta(seconds=1)
        )
        
        async def test_func():
            return "resilient success"
        
        result = await resilient_call(
            test_func,
            circuit_options=circuit_options,
            retry_config=retry_config,
            timeout_config=timeout_config
        )
        
        assert result == "resilient success"


class TestIntegration:
    """Test integration between packages."""
    
    @pytest.mark.asyncio
    async def test_auth_with_circuit_breaker(self):
        """Test authentication with circuit breaker protection."""
        from gauth.circuit import CircuitBreakerOptions
        
        # Create auth config
        auth_config = AuthConfig(
            auth_type=AuthType.JWT,
            extra_config={'secret_key': 'integration_test'}
        )
        
        # Create circuit breaker
        circuit_options = CircuitBreakerOptions(
            name="auth_circuit",
            failure_threshold=2
        )
        circuit = CircuitBreaker(circuit_options)
        
        # Create authenticator
        authenticator = GAuthAuthenticator(auth_config)
        await authenticator.initialize()
        
        # Test with circuit breaker protection
        async def protected_auth():
            request = TokenRequest(
                grant_type="client_credentials",
                subject="circuit_test_user"
            )
            return await authenticator.generate_token(request)
        
        # Should succeed
        result = await circuit.call(protected_auth)
        assert result.access_token is not None
        
        await authenticator.close()
    
    @pytest.mark.asyncio
    async def test_complete_resilience_stack(self):
        """Test complete resilience stack with auth, circuit breaker, retry, and timeout."""
        from gauth.circuit import CircuitBreakerOptions
        
        # Setup components
        auth_config = AuthConfig(
            auth_type=AuthType.JWT,
            extra_config={'secret_key': 'stack_test'}
        )
        
        circuit_options = CircuitBreakerOptions(
            name="stack_circuit",
            failure_threshold=3
        )
        
        retry_config = RetryConfig(
            max_attempts=2,
            initial_delay=timedelta(milliseconds=10)
        )
        
        timeout_config = TimeoutConfig(
            timeout=timedelta(seconds=2)
        )
        
        authenticator = GAuthAuthenticator(auth_config)
        await authenticator.initialize()
        
        # Define protected operation
        async def auth_operation():
            request = TokenRequest(
                grant_type="client_credentials",
                subject="stack_test_user",
                scope="read write"
            )
            response = await authenticator.generate_token(request)
            
            # Also validate the token
            validation = await authenticator.validate_token(response.access_token)
            if not validation.valid:
                raise ValueError("Token validation failed")
            
            return {
                'token': response.access_token,
                'validation': validation.valid,
                'subject': validation.token_data.subject
            }
        
        # Execute with full resilience stack
        result = await resilient_call(
            auth_operation,
            circuit_options=circuit_options,
            retry_config=retry_config,
            timeout_config=timeout_config
        )
        
        assert result['token'] is not None
        assert result['validation'] is True
        assert result['subject'] == "stack_test_user"
        
        await authenticator.close()


if __name__ == "__main__":
    # Run basic smoke tests
    async def run_smoke_tests():
        print("Running smoke tests for new packages...")
        
        # Test auth package
        print("✓ Testing auth package...")
        test_auth = TestAuthPackage()
        test_auth.test_auth_config_creation()
        await test_auth.test_jwt_manager()
        
        # Test circuit package
        print("✓ Testing circuit package...")
        test_circuit = TestCircuitPackage()
        test_circuit.test_circuit_breaker_creation()
        await test_circuit.test_circuit_breaker_success()
        
        # Test resilience package
        print("✓ Testing resilience package...")
        test_resilience = TestResiliencePackage()
        await test_resilience.test_retry_pattern()
        test_resilience.test_rate_limiter()
        
        # Test integration
        print("✓ Testing integration...")
        test_integration = TestIntegration()
        await test_integration.test_auth_with_circuit_breaker()
        
        print("✅ All smoke tests passed!")
    
    asyncio.run(run_smoke_tests())