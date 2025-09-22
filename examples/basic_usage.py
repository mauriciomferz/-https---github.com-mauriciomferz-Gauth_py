"""
Basic GAuth usage example.

This example demonstrates the fundamental GAuth operations:
- Creating a GAuth instance
- Authorization flow
- Token management
- Transaction processing
"""

import asyncio
from datetime import timedelta

from gauth import GAuth, Config
from gauth.core.types import AuthorizationRequest, TokenRequest, Transaction


async def basic_example():
    """Demonstrate basic GAuth usage"""
    print("Basic GAuth Example")
    print("=" * 30)
    
    # 1. Create configuration
    config = Config(
        auth_server_url="https://auth.example.com",
        client_id="basic-example-client",
        client_secret="example-secret",
        scopes=["read", "write"],
        access_token_expiry=timedelta(hours=1),
    )
    
    # 2. Create GAuth instance
    gauth = GAuth.new(config)
    print("✓ Created GAuth instance")
    
    try:
        # 3. Request authorization
        auth_request = AuthorizationRequest(
            client_id="basic-example-client",
            scopes=["read", "write"]
        )
        
        grant = await gauth.initiate_authorization(auth_request)
        print(f"✓ Authorization granted: {grant.grant_id}")
        
        # 4. Request access token
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="basic-example-client"
        )
        
        token_response = await gauth.request_token(token_request)
        print(f"✓ Token issued: {token_response.token[:20]}...")
        
        # 5. Validate token
        access_token = await gauth.validate_token(token_response.token)
        print(f"✓ Token validated for client: {access_token.client_id}")
        
        # 6. Process transaction
        transaction = Transaction(
            transaction_id="basic-001",
            client_id="basic-example-client",
            action="read_data",
            resource="/api/data",
            scope_required=["read"]
        )
        
        result = await gauth.process_transaction(transaction, token_response.token)
        print(f"✓ Transaction processed: {result.success}")
        
        # 7. Check audit logs
        audit_logger = gauth.get_audit_logger()
        events = await audit_logger.get_events()
        print(f"✓ Audit events logged: {len(events)}")
        
    finally:
        # 8. Cleanup
        await gauth.close()
        print("✓ GAuth instance closed")


if __name__ == "__main__":
    asyncio.run(basic_example())