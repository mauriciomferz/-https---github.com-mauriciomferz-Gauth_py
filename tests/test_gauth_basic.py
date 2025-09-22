"""
Basic tests for GAuth core functionality.
"""

import pytest
import asyncio
from datetime import datetime, timedelta

from gauth import GAuth, Config
from gauth.core.types import (
    AuthorizationRequest,
    TokenRequest,
    Transaction,
    GAuthError,
    AuthorizationError,
    TokenError,
    ValidationError,
)


@pytest.fixture
def config():
    """Create a test configuration"""
    return Config(
        auth_server_url="https://test.example.com",
        client_id="test-client",
        client_secret="test-secret",
        scopes=["read", "write"],
        access_token_expiry=timedelta(hours=1),
    )


@pytest.fixture
async def gauth_instance(config):
    """Create a GAuth instance for testing"""
    instance = GAuth.new(config)
    yield instance
    await instance.close()


class TestGAuthBasics:
    """Test basic GAuth functionality"""

    @pytest.mark.asyncio
    async def test_gauth_creation(self, config):
        """Test GAuth instance creation"""
        gauth = GAuth.new(config)
        assert gauth is not None
        assert gauth.config.client_id == "test-client"
        await gauth.close()

    @pytest.mark.asyncio
    async def test_invalid_config(self):
        """Test GAuth creation with invalid config"""
        with pytest.raises(ValueError):
            config = Config(
                auth_server_url="",  # Invalid empty URL
                client_id="test-client",
                client_secret="test-secret",
            )
            config.validate()

    @pytest.mark.asyncio
    async def test_authorization_flow(self, gauth_instance):
        """Test complete authorization flow"""
        # Request authorization
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        assert grant is not None
        assert grant.client_id == "test-client"
        assert "read" in grant.scope
        assert grant.grant_id is not None

    @pytest.mark.asyncio
    async def test_token_request(self, gauth_instance):
        """Test token request and validation"""
        # Get authorization first
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        # Request token
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="test-client"
        )
        
        token_response = await gauth_instance.request_token(token_request)
        
        assert token_response is not None
        assert token_response.token is not None
        assert "read" in token_response.scope
        
        # Validate token
        access_token = await gauth_instance.validate_token(token_response.token)
        assert access_token.client_id == "test-client"
        assert access_token.is_valid

    @pytest.mark.asyncio
    async def test_transaction_processing(self, gauth_instance):
        """Test transaction processing"""
        # Setup authorization and token
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="test-client"
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Process transaction
        transaction = Transaction(
            transaction_id="test-001",
            client_id="test-client",
            action="read_data",
            resource="/api/test",
            scope_required=["read"]
        )
        
        result = await gauth_instance.process_transaction(
            transaction, 
            token_response.token
        )
        
        assert result.success is True
        assert result.transaction_id == "test-001"
        assert result.execution_time_ms is not None

    @pytest.mark.asyncio
    async def test_insufficient_scope(self, gauth_instance):
        """Test transaction with insufficient scope"""
        # Setup authorization and token with limited scope
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="test-client"
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Try transaction requiring write scope
        transaction = Transaction(
            transaction_id="test-002",
            client_id="test-client",
            action="write_data",
            resource="/api/test",
            scope_required=["write"]  # Token only has "read"
        )
        
        result = await gauth_instance.process_transaction(
            transaction, 
            token_response.token
        )
        
        assert result.success is False
        assert "scope" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_invalid_token(self, gauth_instance):
        """Test validation of invalid token"""
        with pytest.raises(TokenError):
            await gauth_instance.validate_token("invalid-token")

    @pytest.mark.asyncio
    async def test_audit_logging(self, gauth_instance):
        """Test audit logging functionality"""
        # Perform some operations
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        await gauth_instance.initiate_authorization(auth_request)
        
        # Check audit logs
        audit_logger = gauth_instance.get_audit_logger()
        events = await audit_logger.get_events()
        
        assert len(events) > 0
        assert any(event.event_type == "auth_request" for event in events)


class TestErrorHandling:
    """Test error handling scenarios"""

    @pytest.mark.asyncio
    async def test_empty_client_id(self, gauth_instance):
        """Test authorization with empty client ID"""
        auth_request = AuthorizationRequest(
            client_id="",
            scopes=["read"]
        )
        
        with pytest.raises(AuthorizationError):
            await gauth_instance.initiate_authorization(auth_request)

    @pytest.mark.asyncio
    async def test_empty_scopes(self, gauth_instance):
        """Test authorization with empty scopes"""
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=[]
        )
        
        with pytest.raises(AuthorizationError):
            await gauth_instance.initiate_authorization(auth_request)

    @pytest.mark.asyncio
    async def test_client_id_mismatch(self, gauth_instance):
        """Test transaction with mismatched client ID"""
        # Setup authorization and token
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="test-client"
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Try transaction with different client ID
        transaction = Transaction(
            transaction_id="test-003",
            client_id="different-client",  # Mismatch
            action="read_data",
            resource="/api/test",
            scope_required=["read"]
        )
        
        result = await gauth_instance.process_transaction(
            transaction, 
            token_response.token
        )
        
        assert result.success is False
        assert "mismatch" in result.error_message.lower()


class TestTokenExpiration:
    """Test token expiration handling"""

    @pytest.mark.asyncio
    async def test_short_lived_token(self):
        """Test token expiration"""
        # Create config with very short token expiry
        config = Config(
            auth_server_url="https://test.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes=["read"],
            access_token_expiry=timedelta(milliseconds=100),  # Very short
        )
        
        gauth = GAuth.new(config)
        
        try:
            # Get authorization and token
            auth_request = AuthorizationRequest(
                client_id="test-client",
                scopes=["read"]
            )
            grant = await gauth.initiate_authorization(auth_request)
            
            token_request = TokenRequest(
                grant_id=grant.grant_id,
                scope=["read"],
                client_id="test-client"
            )
            token_response = await gauth.request_token(token_request)
            
            # Wait for token to expire
            await asyncio.sleep(0.2)
            
            # Try to validate expired token
            with pytest.raises(TokenError):
                await gauth.validate_token(token_response.token)
                
        finally:
            await gauth.close()


if __name__ == "__main__":
    pytest.main([__file__])