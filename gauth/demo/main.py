"""
GAuth Demo Application - Python Implementation

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

GAuth Protocol Compliance: This demo illustrates the GAuth protocol (GiFo-RfC 0111).

This demo shows the basic flow of the GAuth protocol, including:
- Authorization request and grant
- Token issuance
- Transaction processing
- Audit logging
- Token expiration

TODO(RFC 0111):
  - Add demo steps for attestation, notary, version, revocation, and principal/authorizer metadata when supported by the API
  - Add demo for audit log retrieval and verification
  - Add comments mapping demo objects to P*P roles (PEP, PDP, PIP, PAP, PVP)
  - Add demo for subscription and revocation flows if/when supported
"""

import asyncio
import sys
from datetime import datetime, timedelta
from typing import Dict, Any

from gauth.core.gauth import GAuth
from gauth.core.config import Config
from gauth.core.types import (
    AuthorizationRequest,
    TokenRequest,
    Transaction,
    AuditEvent,
)
from gauth.audit.logger import MemoryAuditLogger


async def main():
    """Main demo function"""
    print("GAuth Demo Application - Python Implementation")
    print("=" * 50)
    print()

    # Create a GAuth instance with config
    config = Config(
        auth_server_url="https://auth.example.com",
        client_id="demo-client",
        client_secret="demo-secret",
        scopes=["transaction:execute", "read", "write"],
        access_token_expiry=timedelta(hours=1),
    )

    try:
        auth_service = GAuth.new(config)
        print("✓ Created GAuth instance with config")
        print(f"  - Auth Server URL: {config.auth_server_url}")
        print(f"  - Client ID: {config.client_id}")
        print(f"  - Default Scopes: {', '.join(config.scopes)}")
        print(f"  - Token Expiry: {config.access_token_expiry}")
        print()

    except Exception as e:
        print(f"✗ Error creating GAuth instance: {e}")
        return 1

    # Simulate an authorization request and grant
    print("Step 1: Authorization Request and Grant")
    print("-" * 40)
    
    auth_req = AuthorizationRequest(
        client_id="demo-client",
        scopes=["transaction:execute", "read"],
    )
    
    try:
        grant = await auth_service.initiate_authorization(auth_req)
        print("✓ Authorization granted successfully")
        print(f"  - Grant ID: {grant.grant_id}")
        print(f"  - Client ID: {grant.client_id}")
        print(f"  - Scopes: {', '.join(grant.scope)}")
        print(f"  - Valid Until: {grant.valid_until}")
        print()
        
    except Exception as e:
        print(f"✗ Authorization failed: {e}")
        return 1

    # Request an access token
    print("Step 2: Token Request")
    print("-" * 40)
    
    token_req = TokenRequest(
        grant_id=grant.grant_id,
        scope=["transaction:execute"],
        client_id="demo-client",
    )
    
    try:
        token_response = await auth_service.request_token(token_req)
        print("✓ Token issued successfully")
        print(f"  - Token: {token_response.token[:20]}...")
        print(f"  - Valid Until: {token_response.valid_until}")
        print(f"  - Scope: {', '.join(token_response.scope)}")
        print()
        
    except Exception as e:
        print(f"✗ Token request failed: {e}")
        return 1

    # Validate the token
    print("Step 3: Token Validation")
    print("-" * 40)
    
    try:
        access_token = await auth_service.validate_token(token_response.token)
        print("✓ Token validated successfully")
        print(f"  - Client ID: {access_token.client_id}")
        print(f"  - Scopes: {', '.join(access_token.scope)}")
        print(f"  - Expires At: {access_token.expires_at}")
        print(f"  - Is Valid: {access_token.is_valid}")
        print()
        
    except Exception as e:
        print(f"✗ Token validation failed: {e}")
        return 1

    # Process a transaction
    print("Step 4: Transaction Processing")
    print("-" * 40)
    
    transaction = Transaction(
        transaction_id="demo-tx-001",
        client_id="demo-client",
        action="read_data",
        resource="/api/users/123",
        parameters={"format": "json", "include_metadata": True},
        scope_required=["read"],
    )
    
    try:
        result = await auth_service.process_transaction(transaction, token_response.token)
        print("✓ Transaction processed successfully")
        print(f"  - Transaction ID: {result.transaction_id}")
        print(f"  - Success: {result.success}")
        print(f"  - Execution Time: {result.execution_time_ms:.2f}ms")
        if result.result_data:
            print(f"  - Result: {result.result_data}")
        print()
        
    except Exception as e:
        print(f"✗ Transaction processing failed: {e}")
        return 1

    # Demonstrate failed transaction (insufficient scope)
    print("Step 5: Failed Transaction (Insufficient Scope)")
    print("-" * 40)
    
    failed_transaction = Transaction(
        transaction_id="demo-tx-002",
        client_id="demo-client",
        action="write_data",
        resource="/api/users/123",
        parameters={"data": {"name": "Updated Name"}},
        scope_required=["write"],  # Token only has "transaction:execute" scope
    )
    
    result = await auth_service.process_transaction(failed_transaction, token_response.token)
    if not result.success:
        print("✓ Transaction correctly rejected (insufficient scope)")
        print(f"  - Transaction ID: {result.transaction_id}")
        print(f"  - Success: {result.success}")
        print(f"  - Error: {result.error_message}")
        print()

    # Retrieve and display audit logs
    print("Step 6: Audit Log Retrieval")
    print("-" * 40)
    
    try:
        audit_logger = auth_service.get_audit_logger()
        events = await audit_logger.get_events()
        
        print(f"✓ Retrieved {len(events)} audit events")
        
        for i, event in enumerate(events, 1):
            print(f"  Event {i}:")
            print(f"    - Type: {event.event_type}")
            print(f"    - Client ID: {event.client_id}")
            print(f"    - Timestamp: {event.timestamp}")
            print(f"    - Details: {event.details}")
            print()
            
    except Exception as e:
        print(f"✗ Audit log retrieval failed: {e}")
        return 1

    # Demonstrate token expiration
    print("Step 7: Token Expiration Simulation")
    print("-" * 40)
    
    # Create a short-lived token for demonstration
    short_config = Config(
        auth_server_url="https://auth.example.com",
        client_id="demo-client",
        client_secret="demo-secret",
        scopes=["read"],
        access_token_expiry=timedelta(seconds=1),  # Very short expiry
    )
    
    short_auth_service = GAuth.new(short_config)
    
    # Get authorization and token
    short_grant = await short_auth_service.initiate_authorization(
        AuthorizationRequest(client_id="demo-client", scopes=["read"])
    )
    
    short_token_response = await short_auth_service.request_token(
        TokenRequest(grant_id=short_grant.grant_id, scope=["read"], client_id="demo-client")
    )
    
    print(f"✓ Created short-lived token: {short_token_response.token[:20]}...")
    print("  - Waiting for token to expire...")
    
    # Wait for token to expire
    await asyncio.sleep(2)
    
    try:
        await short_auth_service.validate_token(short_token_response.token)
        print("✗ Token should have expired but validation succeeded")
    except Exception as e:
        print("✓ Token correctly expired and validation failed")
        print(f"  - Error: {e}")
        print()

    # Cleanup
    print("Step 8: Cleanup")
    print("-" * 40)
    
    try:
        await auth_service.close()
        await short_auth_service.close()
        print("✓ GAuth instances closed successfully")
        print()
        
    except Exception as e:
        print(f"✗ Cleanup failed: {e}")
        return 1

    print("Demo completed successfully! 🎉")
    print()
    print("This demo illustrated:")
    print("- ✓ Authorization request and grant")
    print("- ✓ Token issuance and validation")
    print("- ✓ Transaction processing with scope validation")
    print("- ✓ Audit logging and retrieval")
    print("- ✓ Token expiration handling")
    print()
    print("For more advanced features, see the examples/ directory.")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)