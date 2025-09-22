"""
Enhanced comprehensive tests for GAuth Python implementation.

This test suite validates complete GAuth protocol compliance including
all the functionality that was missing from the initial conversion.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)

from gauth import GAuth, Config
from gauth.core.types import (
    AuthorizationRequest,
    TokenRequest,
    Transaction,
    TransactionResult,
    AuditEvent,
    GAuthError,
    AuthorizationError,
    TokenError,
    ValidationError,
    TransactionError,
)
from gauth.events import EventBus, Event, EventType, EventAction
from gauth.transaction import TransactionProcessor, TransactionContext
from gauth.service import Service
from gauth.errors import ErrorCode


@pytest.fixture
def config():
    """Create a test configuration."""
    return Config(
        auth_server_url="https://auth.example.com",
        client_id="test-client",
        client_secret="test-secret",
        scopes=["read", "write", "transaction:execute"],
        access_token_expiry=timedelta(hours=1),
    )


@pytest.fixture
async def gauth_instance(config):
    """Create a GAuth instance for testing."""
    gauth = GAuth.new(config)
    yield gauth
    await gauth.close()


@pytest.fixture
async def service_instance(config):
    """Create a Service instance for testing."""
    service = Service(config)
    await service.start()
    yield service
    await service.stop()


class TestGAuthEnhanced:
    """Enhanced tests for complete GAuth functionality."""
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_config_validation(self, config):
        """Test configuration validation."""
        # Valid config should work
        gauth = GAuth.new(config)
        assert gauth is not None
        await gauth.close()
        
        # Invalid config should raise error
        invalid_config = Config(
            auth_server_url="",  # Invalid empty URL
            client_id="",        # Invalid empty client ID
            client_secret="test-secret",
            scopes=[],           # Invalid empty scopes
        )
        
        with pytest.raises(ValidationError):
            invalid_config.validate()
    
    @pytest.mark.asyncio
    async def test_authorization_flow_complete(self, gauth_instance):
        """Test complete authorization flow."""
        # Test authorization request
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read", "write"]
        )
        
        grant = await gauth_instance.initiate_authorization(auth_request)
        assert grant is not None
        assert grant.grant_id is not None
        assert grant.client_id == "test-client"
        assert "read" in grant.scope
        assert "write" in grant.scope
        assert grant.valid_until > datetime.now()
    
    @pytest.mark.asyncio
    async def test_token_lifecycle(self, gauth_instance):
        """Test complete token lifecycle: issue, validate, revoke."""
        # First get authorization
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read", "write"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        # Issue token
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["read"]
        )
        token_response = await gauth_instance.request_token(token_request)
        
        assert token_response is not None
        assert token_response.token is not None
        assert token_response.scope == ["read"]
        assert token_response.valid_until > datetime.now()
        
        # Validate token
        access_token = await gauth_instance.validate_token(token_response.token)
        assert access_token is not None
        assert access_token.client_id == "test-client"
        assert access_token.scope == ["read"]
        assert access_token.is_valid
        
        # Revoke token
        revoked = await gauth_instance.revoke_token(token_response.token)
        assert revoked is True
        
        # Token should no longer be valid
        with pytest.raises(TokenError):
            await gauth_instance.validate_token(token_response.token)
    
    @pytest.mark.asyncio
    async def test_transaction_processing(self, gauth_instance):
        """Test transaction processing with authorization."""
        # Get authorization and token
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read", "transaction:execute"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["read", "transaction:execute"]
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Process transaction
        transaction = Transaction(
            transaction_id="test-tx-001",
            client_id="test-client",
            action="read_data",
            resource="/api/users/123",
            scope_required=["read"]
        )
        
        result = await gauth_instance.process_transaction(transaction, token_response.token)
        
        assert result is not None
        assert result.success is True
        assert result.transaction_id == "test-tx-001"
        assert result.execution_time_ms >= 0
    
    @pytest.mark.asyncio
    async def test_insufficient_scope_transaction(self, gauth_instance):
        """Test transaction fails with insufficient scope."""
        # Get authorization with limited scope
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]  # Only read, no write
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["read"]
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Try transaction requiring write scope
        transaction = Transaction(
            transaction_id="test-tx-002",
            client_id="test-client",
            action="write_data",
            resource="/api/users/123",
            scope_required=["write"]  # Requires write scope
        )
        
        result = await gauth_instance.process_transaction(transaction, token_response.token)
        
        assert result is not None
        assert result.success is False
        assert "Insufficient scope" in result.error_message
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, gauth_instance):
        """Test audit logging functionality."""
        # Perform some operations
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["read"]
        )
        await gauth_instance.request_token(token_request)
        
        # Check audit logs
        audit_logger = gauth_instance.get_audit_logger()
        events = await audit_logger.get_events()
        
        assert len(events) >= 2  # At least auth and token events
        
        # Check for auth event
        auth_events = [e for e in events if e.event_type == "auth_request"]
        assert len(auth_events) >= 1
        assert auth_events[0].client_id == "test-client"
        
        # Check for token event
        token_events = [e for e in events if e.event_type == "token_issued"]
        assert len(token_events) >= 1
        assert token_events[0].client_id == "test-client"


class TestEventSystem:
    """Test the event system functionality."""
    
    @pytest.mark.asyncio
    async def test_event_bus_lifecycle(self):
        """Test event bus start/stop lifecycle."""
        event_bus = EventBus()
        
        # Initially not running
        assert not event_bus._running
        
        # Start
        await event_bus.start()
        assert event_bus._running
        
        # Stop
        await event_bus.stop()
        assert not event_bus._running
    
    @pytest.mark.asyncio
    async def test_event_publishing_and_handling(self):
        """Test event publishing and handling."""
        event_bus = EventBus()
        await event_bus.start()
        
        events_received = []
        
        def event_handler(event):
            events_received.append(event)
        
        # Subscribe to events
        event_bus.subscribe_function(EventType.AUTH_REQUEST, event_handler)
        
        # Publish event
        test_event = Event(
            type=EventType.AUTH_REQUEST,
            action=EventAction.CREATE,
            subject="test-client",
            resource="authorization"
        )
        
        await event_bus.publish(test_event)
        
        # Give event processing time
        await asyncio.sleep(0.1)
        
        assert len(events_received) == 1
        assert events_received[0].subject == "test-client"
        
        await event_bus.stop()


class TestTransactionProcessor:
    """Test the transaction processor functionality."""
    
    @pytest.mark.asyncio
    async def test_transaction_validation(self, gauth_instance):
        """Test transaction validation."""
        processor = TransactionProcessor(gauth_instance)
        
        # Valid transaction
        transaction = Transaction(
            transaction_id="test-tx-001",
            client_id="test-client",
            action="read_data",
            resource="/api/data"
        )
        
        context = TransactionContext(
            client_id="test-client",
            user_id="test-user"
        )
        
        # Should process without token (no authorization required for basic read)
        result = await processor.process_transaction(transaction, context)
        assert result is not None
        assert result.transaction_id == "test-tx-001"
    
    @pytest.mark.asyncio
    async def test_transaction_with_authorization(self, gauth_instance):
        """Test transaction processing with authorization token."""
        processor = TransactionProcessor(gauth_instance)
        
        # Get token first
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["write"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["write"]
        )
        token_response = await gauth_instance.request_token(token_request)
        
        # Process transaction with token
        transaction = Transaction(
            transaction_id="test-tx-002",
            client_id="test-client",
            action="write_data",
            resource="/api/data"
        )
        
        context = TransactionContext(
            client_id="test-client",
            user_id="test-user"
        )
        
        result = await processor.process_transaction(
            transaction, 
            context, 
            token=token_response.token
        )
        
        assert result is not None
        assert result.success is True
        assert result.transaction_id == "test-tx-002"


class TestServiceLayer:
    """Test the service layer functionality."""
    
    @pytest.mark.asyncio
    async def test_service_lifecycle(self, config):
        """Test service start/stop lifecycle."""
        service = Service(config)
        
        # Initially not running
        assert not service._running
        
        # Start service
        await service.start()
        assert service._running
        
        # Check service status
        status = service.get_service_status()
        assert status["running"] is True
        assert status["client_id"] == "test-client"
        
        # Stop service
        await service.stop()
        assert not service._running
    
    @pytest.mark.asyncio
    async def test_service_authorization_flow(self, service_instance):
        """Test authorization through service layer."""
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read", "write"]
        )
        
        grant = await service_instance.authorize(auth_request)
        
        assert grant is not None
        assert grant.client_id == "test-client"
        assert "read" in grant.scope
        assert "write" in grant.scope
        
        # Should be stored in service
        stored_grant = service_instance.get_grant(grant.grant_id)
        assert stored_grant is not None
        assert stored_grant.grant_id == grant.grant_id
    
    @pytest.mark.asyncio
    async def test_service_token_flow(self, service_instance):
        """Test token issuance through service layer."""
        # First get authorization
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await service_instance.authorize(auth_request)
        
        # Request token
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            client_id="test-client",
            scope=["read"]
        )
        token_response = await service_instance.request_token(token_request)
        
        assert token_response is not None
        assert token_response.token is not None
        assert token_response.scope == ["read"]
        
        # Validate token through service
        access_token = await service_instance.validate_token(token_response.token)
        assert access_token is not None
        assert access_token.client_id == "test-client"
    
    @pytest.mark.asyncio
    async def test_service_health_check(self, service_instance):
        """Test service health check."""
        health = await service_instance.health_check()
        
        assert health["service"] == "healthy"
        assert "components" in health
        assert "timestamp" in health


class TestErrorHandling:
    """Test enhanced error handling."""
    
    @pytest.mark.asyncio
    async def test_invalid_token_error(self, gauth_instance):
        """Test invalid token error handling."""
        with pytest.raises(TokenError) as exc_info:
            await gauth_instance.validate_token("invalid-token")
        
        error = exc_info.value
        assert "Token not found" in str(error)
    
    @pytest.mark.asyncio
    async def test_authorization_error(self, gauth_instance):
        """Test authorization error handling."""
        # Invalid authorization request
        invalid_request = AuthorizationRequest(
            client_id="",  # Empty client ID
            scopes=["read"]
        )
        
        with pytest.raises(AuthorizationError):
            await gauth_instance.initiate_authorization(invalid_request)
    
    @pytest.mark.asyncio
    async def test_rate_limiting_error(self, gauth_instance):
        """Test rate limiting functionality."""
        # This would require a more restrictive rate limiter
        # For now, just test that the interface works
        auth_request = AuthorizationRequest(
            client_id="test-client",
            scopes=["read"]
        )
        grant = await gauth_instance.initiate_authorization(auth_request)
        
        # Multiple rapid token requests
        for i in range(5):
            token_request = TokenRequest(
                grant_id=grant.grant_id,
                client_id="test-client",
                scope=["read"]
            )
            # Should succeed with default rate limiter
            token_response = await gauth_instance.request_token(token_request)
            assert token_response is not None


class TestIntegration:
    """Integration tests for complete functionality."""
    
    @pytest.mark.asyncio
    async def test_complete_workflow(self, config):
        """Test complete GAuth workflow from service to transaction."""
        # Create service
        service = Service(config)
        await service.start()
        
        try:
            # 1. Authorization
            auth_request = AuthorizationRequest(
                client_id="test-client",
                scopes=["read", "write", "transaction:execute"]
            )
            grant = await service.authorize(auth_request)
            
            # 2. Token issuance
            token_request = TokenRequest(
                grant_id=grant.grant_id,
                client_id="test-client",
                scope=["read", "transaction:execute"]
            )
            token_response = await service.request_token(token_request)
            
            # 3. Token validation
            access_token = await service.validate_token(token_response.token)
            assert access_token.client_id == "test-client"
            
            # 4. Transaction processing
            transaction = Transaction(
                transaction_id="integration-test-001",
                client_id="test-client",
                action="read_data",
                resource="/api/integration/test",
                scope_required=["read"]
            )
            
            context = TransactionContext(
                client_id="test-client",
                user_id="integration-test-user"
            )
            
            result = await service.transaction_processor.process_transaction(
                transaction, context, token=token_response.token
            )
            
            assert result.success is True
            assert result.transaction_id == "integration-test-001"
            
            # 5. Token revocation
            revoked = await service.revoke_token(token_response.token)
            assert revoked is True
            
            # 6. Verify token is no longer valid
            with pytest.raises(TokenError):
                await service.validate_token(token_response.token)
        
        finally:
            await service.stop()
    
    @pytest.mark.asyncio
    async def test_audit_trail_complete(self, config):
        """Test complete audit trail across all operations."""
        service = Service(config)
        await service.start()
        
        try:
            # Perform operations
            auth_request = AuthorizationRequest(
                client_id="audit-test-client",
                scopes=["read", "write"]
            )
            grant = await service.authorize(auth_request)
            
            token_request = TokenRequest(
                grant_id=grant.grant_id,
                client_id="audit-test-client",
                scope=["read"]
            )
            token_response = await service.request_token(token_request)
            
            transaction = Transaction(
                transaction_id="audit-test-001",
                client_id="audit-test-client",
                action="read_data",
                resource="/api/audit/test"
            )
            
            await service.gauth.process_transaction(transaction, token_response.token)
            
            # Check audit logs
            audit_logger = service.gauth.get_audit_logger()
            events = await audit_logger.get_events()
            
            # Should have multiple events
            assert len(events) >= 3
            
            # Check event types
            event_types = [e.event_type for e in events]
            assert "auth_request" in event_types
            assert "token_issued" in event_types
            assert "transaction" in event_types
            
            # All events should have correct client_id
            for event in events:
                assert event.client_id == "audit-test-client"
        
        finally:
            await service.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])