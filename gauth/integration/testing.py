"""
Testing utilities for GAuth integration testing.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

from ..auth import AuthManager, AuthConfig, TokenRequest, TokenResponse
from ..core import GAuth, Config
from ..token import TokenManager, TokenStore
from ..store import MemoryTokenStore
from .clients import IntegrationManager


@dataclass
class TestConfig:
    """Configuration for integration tests."""
    test_timeout: int = 30
    setup_timeout: int = 10
    cleanup_timeout: int = 5
    parallel_tests: bool = True
    mock_external_services: bool = True
    log_level: str = "INFO"
    
    
@dataclass
class TestResult:
    """Result of an integration test."""
    test_name: str
    success: bool
    duration: float
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class MockExternalService:
    """Mock external service for testing."""
    
    def __init__(self, name: str, response_delay: float = 0.1):
        self.name = name
        self.response_delay = response_delay
        self.call_count = 0
        self.last_request = None
        self.responses = {}
        self.errors = {}
    
    def set_response(self, method: str, response: Any) -> None:
        """Set mock response for a method."""
        self.responses[method] = response
    
    def set_error(self, method: str, error: Exception) -> None:
        """Set mock error for a method."""
        self.errors[method] = error
    
    async def call(self, method: str, *args, **kwargs) -> Any:
        """Simulate external service call."""
        self.call_count += 1
        self.last_request = {"method": method, "args": args, "kwargs": kwargs}
        
        # Simulate network delay
        await asyncio.sleep(self.response_delay)
        
        # Check for configured errors
        if method in self.errors:
            raise self.errors[method]
        
        # Return configured response or default
        return self.responses.get(method, {"status": "success", "method": method})


class TestEnvironment:
    """Test environment for integration testing."""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.TestEnvironment")
        self.gauth: Optional[GAuth] = None
        self.integration_manager: Optional[IntegrationManager] = None
        self.mock_services: Dict[str, MockExternalService] = {}
        self.test_results: List[TestResult] = []
    
    async def setup(self) -> None:
        """Set up test environment."""
        self.logger.info("Setting up test environment")
        
        # Create GAuth instance with test configuration
        gauth_config = Config(
            auth_server_url="http://localhost:8080",
            client_id="test-client",
            client_secret="test-secret",
            scopes=["read", "write", "admin"]
        )
        
        self.gauth = GAuth.new(gauth_config)
        
        # Set up integration manager
        self.integration_manager = IntegrationManager()
        
        # Set up mock services if configured
        if self.config.mock_external_services:
            await self._setup_mock_services()
    
    async def cleanup(self) -> None:
        """Clean up test environment."""
        self.logger.info("Cleaning up test environment")
        
        if self.gauth:
            await self.gauth.close()
        
        if self.integration_manager:
            await self.integration_manager.disconnect_all()
        
        self.mock_services.clear()
    
    async def _setup_mock_services(self) -> None:
        """Set up mock external services."""
        # Mock database service
        db_mock = MockExternalService("database", 0.05)
        db_mock.set_response("query", {"rows": [], "affected": 0})
        self.mock_services["database"] = db_mock
        
        # Mock Redis service
        redis_mock = MockExternalService("redis", 0.02)
        redis_mock.set_response("get", None)
        redis_mock.set_response("set", True)
        self.mock_services["redis"] = redis_mock
        
        # Mock HTTP API service
        api_mock = MockExternalService("api", 0.1)
        api_mock.set_response("get", {"data": "test"})
        self.mock_services["api"] = api_mock
    
    async def run_test(self, test_name: str, test_func: Callable) -> TestResult:
        """Run a single integration test."""
        self.logger.info(f"Running test: {test_name}")
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(
                test_func(self),
                timeout=self.config.test_timeout
            )
            
            duration = time.time() - start_time
            test_result = TestResult(
                test_name=test_name,
                success=True,
                duration=duration,
                metadata={"result": result}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            test_result = TestResult(
                test_name=test_name,
                success=False,
                duration=duration,
                error_message=str(e)
            )
            self.logger.error(f"Test {test_name} failed: {e}")
        
        self.test_results.append(test_result)
        return test_result
    
    async def run_test_suite(self, tests: Dict[str, Callable]) -> List[TestResult]:
        """Run a suite of integration tests."""
        self.logger.info(f"Running test suite with {len(tests)} tests")
        
        if self.config.parallel_tests:
            # Run tests in parallel
            tasks = [
                self.run_test(name, func)
                for name, func in tests.items()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle any exceptions from gather
            test_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    test_name = list(tests.keys())[i]
                    test_results.append(TestResult(
                        test_name=test_name,
                        success=False,
                        duration=0,
                        error_message=str(result)
                    ))
                else:
                    test_results.append(result)
            
            return test_results
        else:
            # Run tests sequentially
            results = []
            for name, func in tests.items():
                result = await self.run_test(name, func)
                results.append(result)
            
            return results


class IntegrationTestRunner:
    """Runner for integration tests."""
    
    def __init__(self, config: Optional[TestConfig] = None):
        self.config = config or TestConfig()
        self.logger = logging.getLogger(f"{__name__}.IntegrationTestRunner")
    
    @asynccontextmanager
    async def test_environment(self) -> AsyncGenerator[TestEnvironment, None]:
        """Context manager for test environment."""
        env = TestEnvironment(self.config)
        try:
            await env.setup()
            yield env
        finally:
            await env.cleanup()
    
    async def run_token_management_tests(self) -> List[TestResult]:
        """Run token management integration tests."""
        async def test_token_creation(env: TestEnvironment) -> Dict[str, Any]:
            """Test token creation flow."""
            # Create token request
            token_request = TokenRequest(
                grant_id="test-grant-001",
                client_id="test-client",
                scope=["read", "write"]
            )
            
            # Request token
            token_response = await env.gauth.request_token(token_request)
            
            assert token_response is not None
            assert token_response.token is not None
            assert token_response.scope == ["read", "write"]
            
            return {"token_length": len(token_response.token)}
        
        async def test_token_validation(env: TestEnvironment) -> Dict[str, Any]:
            """Test token validation flow."""
            # First create a token
            token_request = TokenRequest(
                grant_id="test-grant-002",
                client_id="test-client",
                scope=["read"]
            )
            
            token_response = await env.gauth.request_token(token_request)
            
            # Validate the token
            access_token = await env.gauth.validate_token(token_response.token)
            
            assert access_token is not None
            assert access_token.client_id == "test-client"
            assert "read" in access_token.scope
            
            return {"validated": True}
        
        async def test_token_revocation(env: TestEnvironment) -> Dict[str, Any]:
            """Test token revocation flow."""
            # Create token
            token_request = TokenRequest(
                grant_id="test-grant-003",
                client_id="test-client",
                scope=["admin"]
            )
            
            token_response = await env.gauth.request_token(token_request)
            
            # Revoke token
            await env.gauth.revoke_token(token_response.token)
            
            # Try to validate revoked token (should fail)
            try:
                await env.gauth.validate_token(token_response.token)
                assert False, "Validation should have failed for revoked token"
            except Exception:
                pass  # Expected
            
            return {"revoked": True}
        
        tests = {
            "token_creation": test_token_creation,
            "token_validation": test_token_validation,
            "token_revocation": test_token_revocation
        }
        
        async with self.test_environment() as env:
            return await env.run_test_suite(tests)
    
    async def run_authentication_tests(self) -> List[TestResult]:
        """Run authentication integration tests."""
        async def test_basic_auth(env: TestEnvironment) -> Dict[str, Any]:
            """Test basic authentication flow."""
            # Simulate basic authentication
            await asyncio.sleep(0.1)  # Simulate auth time
            return {"auth_method": "basic", "success": True}
        
        async def test_jwt_auth(env: TestEnvironment) -> Dict[str, Any]:
            """Test JWT authentication flow."""
            # Simulate JWT authentication
            await asyncio.sleep(0.1)
            return {"auth_method": "jwt", "success": True}
        
        tests = {
            "basic_auth": test_basic_auth,
            "jwt_auth": test_jwt_auth
        }
        
        async with self.test_environment() as env:
            return await env.run_test_suite(tests)
    
    async def run_external_service_tests(self) -> List[TestResult]:
        """Run external service integration tests."""
        async def test_database_integration(env: TestEnvironment) -> Dict[str, Any]:
            """Test database integration."""
            if "database" in env.mock_services:
                db_mock = env.mock_services["database"]
                result = await db_mock.call("query", "SELECT * FROM users")
                return {"db_calls": db_mock.call_count, "result": result}
            return {"skipped": "No database mock"}
        
        async def test_redis_integration(env: TestEnvironment) -> Dict[str, Any]:
            """Test Redis integration."""
            if "redis" in env.mock_services:
                redis_mock = env.mock_services["redis"]
                await redis_mock.call("set", "test_key", "test_value")
                result = await redis_mock.call("get", "test_key")
                return {"redis_calls": redis_mock.call_count, "result": result}
            return {"skipped": "No Redis mock"}
        
        tests = {
            "database_integration": test_database_integration,
            "redis_integration": test_redis_integration
        }
        
        async with self.test_environment() as env:
            return await env.run_test_suite(tests)
    
    async def run_all_tests(self) -> Dict[str, List[TestResult]]:
        """Run all integration tests."""
        self.logger.info("Running all integration tests")
        
        results = {
            "token_management": await self.run_token_management_tests(),
            "authentication": await self.run_authentication_tests(),
            "external_services": await self.run_external_service_tests()
        }
        
        # Log summary
        total_tests = sum(len(test_results) for test_results in results.values())
        successful_tests = sum(
            sum(1 for result in test_results if result.success)
            for test_results in results.values()
        )
        
        self.logger.info(
            f"Integration tests completed: {successful_tests}/{total_tests} passed"
        )
        
        return results


# Utility functions for testing
async def create_test_gauth_instance() -> GAuth:
    """Create a GAuth instance for testing."""
    config = Config(
        auth_server_url="http://localhost:8080",
        client_id="test-client",
        client_secret="test-secret",
        scopes=["read", "write"]
    )
    return GAuth.new(config)


async def create_test_token_store() -> TokenStore:
    """Create a token store for testing."""
    return MemoryTokenStore()


def assert_test_result(result: TestResult, expected_success: bool = True) -> None:
    """Assert test result matches expectations."""
    assert result.success == expected_success, f"Test {result.test_name} failed: {result.error_message}"
    assert result.duration >= 0, "Test duration should be non-negative"