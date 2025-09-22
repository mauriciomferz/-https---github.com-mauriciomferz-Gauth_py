"""
Advanced GAuth features example.

This example demonstrates advanced GAuth features:
- Custom audit logging
- Rate limiting
- Token restrictions
- Error handling
"""

import asyncio
from datetime import timedelta, datetime

from gauth import GAuth, Config
from gauth.core.types import (
    AuthorizationRequest, 
    TokenRequest, 
    Transaction,
    Restriction,
    AuditEvent
)
from gauth.audit.logger import FileAuditLogger
from gauth.ratelimit.limiter import TokenBucketRateLimiter


async def advanced_example():
    """Demonstrate advanced GAuth features"""
    print("Advanced GAuth Example")
    print("=" * 30)
    
    # 1. Create configuration with custom settings
    config = Config(
        auth_server_url="https://auth.example.com",
        client_id="advanced-example-client",
        client_secret="advanced-secret",
        scopes=["read", "write", "admin"],
        access_token_expiry=timedelta(minutes=30),
    )
    
    # 2. Create custom components
    audit_logger = FileAuditLogger("audit_advanced.log")
    rate_limiter = TokenBucketRateLimiter(
        max_requests=10,
        time_window=timedelta(minutes=1),
        burst_limit=5
    )
    
    # 3. Create GAuth instance with custom components
    gauth = GAuth.new(
        config,
        audit_logger=audit_logger,
        rate_limiter=rate_limiter
    )
    print("✓ Created GAuth instance with custom components")
    
    try:
        # 4. Request authorization with restrictions
        auth_request = AuthorizationRequest(
            client_id="advanced-example-client",
            scopes=["read", "write"]
        )
        
        grant = await gauth.initiate_authorization(auth_request)
        print(f"✓ Authorization granted: {grant.grant_id}")
        
        # 5. Request token with restrictions
        restrictions = [
            Restriction(type="ip", value="192.168.1.0/24", description="Local network only"),
            Restriction(type="time_window", value="09:00-17:00", description="Business hours only"),
        ]
        
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="advanced-example-client",
            restrictions=restrictions
        )
        
        token_response = await gauth.request_token(token_request)
        print(f"✓ Token issued with restrictions: {len(token_response.restrictions)}")
        
        # 6. Test rate limiting
        print("Testing rate limiting...")
        for i in range(15):  # Exceed the rate limit
            try:
                test_token_request = TokenRequest(
                    grant_id=grant.grant_id,
                    scope=["read"],
                    client_id="advanced-example-client"
                )
                await gauth.request_token(test_token_request)
                print(f"  Request {i+1}: ✓ Allowed")
            except Exception as e:
                print(f"  Request {i+1}: ✗ Rate limited - {e}")
                break
        
        # 7. Process multiple transactions
        transactions = [
            Transaction(
                transaction_id=f"adv-{i:03d}",
                client_id="advanced-example-client",
                action="read_data",
                resource=f"/api/data/{i}",
                scope_required=["read"]
            )
            for i in range(3)
        ]
        
        print("Processing multiple transactions...")
        for transaction in transactions:
            result = await gauth.process_transaction(transaction, token_response.token)
            status = "✓" if result.success else "✗"
            print(f"  Transaction {transaction.transaction_id}: {status}")
        
        # 8. Custom audit event
        custom_event = AuditEvent(
            event_id="custom-001",
            event_type="custom_operation",
            client_id="advanced-example-client",
            details={
                "operation": "advanced_example_completed",
                "timestamp": datetime.now().isoformat(),
                "metadata": {"version": "1.0", "features": ["restrictions", "rate_limiting"]}
            }
        )
        
        await audit_logger.log(custom_event)
        print("✓ Custom audit event logged")
        
        # 9. Retrieve filtered audit events
        events = await audit_logger.get_events(
            client_id="advanced-example-client",
            event_type="token_issued"
        )
        print(f"✓ Retrieved {len(events)} token issuance events")
        
        # 10. Error handling demonstration
        print("Demonstrating error handling...")
        
        try:
            # Try to validate an invalid token
            await gauth.validate_token("invalid-token")
        except Exception as e:
            print(f"  ✓ Invalid token correctly rejected: {type(e).__name__}")
        
        try:
            # Try to process transaction with insufficient scope
            high_privilege_tx = Transaction(
                transaction_id="adv-admin-001",
                client_id="advanced-example-client",
                action="admin_operation",
                resource="/api/admin",
                scope_required=["admin"]  # Token only has "read" scope
            )
            
            result = await gauth.process_transaction(high_privilege_tx, token_response.token)
            if not result.success:
                print(f"  ✓ Insufficient scope correctly handled: {result.error_message}")
        
        except Exception as e:
            print(f"  ✓ Transaction error correctly handled: {type(e).__name__}")
        
    finally:
        # 11. Cleanup
        await gauth.close()
        print("✓ GAuth instance closed")


if __name__ == "__main__":
    asyncio.run(advanced_example())