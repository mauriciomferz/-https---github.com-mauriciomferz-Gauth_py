#!/usr/bin/env python3
"""
Authentication Examples for GAuth

This example demonstrates various authentication methods supported by GAuth:
- JWT authentication
- OAuth2 authentication 
- PASETO authentication
- Basic authentication

Run this example to see how different auth methods work.
"""

import asyncio
import logging
from datetime import timedelta

from gauth.auth import (
    AuthService, AuthServiceConfig, AuthType,
    TokenRequest, create_auth_service
)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def demo_jwt_auth():
    """Demonstrate JWT authentication."""
    print("\n=== JWT Authentication Demo ===")
    
    # Create JWT auth service
    config = AuthServiceConfig(
        auth_type=AuthType.JWT,
        secret_key="demo-jwt-secret-key",
        access_token_expiry=timedelta(hours=1),
        issuer="gauth-demo",
        audience="demo-client"
    )
    
    auth_service = AuthService(config)
    await auth_service.initialize()
    
    # Generate token
    token_request = TokenRequest(
        grant_type="client_credentials",
        subject="demo-user",
        scope="read write",
        audience="demo-client"
    )
    
    try:
        token_response = await auth_service.generate_token(token_request)
        print(f"✓ JWT Token generated: {token_response.access_token[:20]}...")
        print(f"  Token type: {token_response.token_type}")
        print(f"  Expires in: {token_response.expires_in} seconds")
        
        # Validate token
        token_data = await auth_service.validate_token(token_response.access_token)
        if token_data:
            print(f"✓ Token validated successfully")
            print(f"  User ID: {token_data.user_id}")
            print(f"  Client ID: {token_data.client_id}")
            print(f"  Scopes: {token_data.scopes}")
        else:
            print("✗ Token validation failed")
            
        # Revoke token
        success = await auth_service.revoke_token(token_response.access_token, "demo_complete")
        print(f"✓ Token revoked: {success}")
        
    except Exception as e:
        print(f"✗ JWT demo failed: {e}")


async def demo_oauth2_auth():
    """Demonstrate OAuth2 authentication."""
    print("\n=== OAuth2 Authentication Demo ===")
    
    # Create OAuth2 auth service
    config = AuthServiceConfig(
        auth_type=AuthType.OAUTH2,
        secret_key="demo-oauth2-secret",
        access_token_expiry=timedelta(hours=2),
        extra_config={
            "client_id": "demo-client-id",
            "client_secret": "demo-client-secret",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token"
        }
    )
    
    auth_service = AuthService(config)
    await auth_service.initialize()
    
    # Generate token (client credentials flow)
    token_request = TokenRequest(
        grant_type="client_credentials",
        subject="oauth2-client",
        scope="api:read api:write",
        client_id="demo-client-id"
    )
    
    try:
        token_response = await auth_service.generate_token(token_request)
        print(f"✓ OAuth2 Token generated: {token_response.access_token[:20]}...")
        print(f"  Scope: {token_response.scope}")
        
        # Validate token
        token_data = await auth_service.validate_token(token_response.access_token)
        if token_data:
            print(f"✓ OAuth2 token validated successfully")
        else:
            print("✗ OAuth2 token validation failed")
            
    except Exception as e:
        print(f"✗ OAuth2 demo failed: {e}")


async def demo_paseto_auth():
    """Demonstrate PASETO authentication."""
    print("\n=== PASETO Authentication Demo ===")
    
    # Create PASETO auth service
    config = AuthServiceConfig(
        auth_type=AuthType.PASETO,
        secret_key="demo-paseto-secret-key-32bytes!",
        access_token_expiry=timedelta(minutes=30),
        issuer="gauth-paseto-demo"
    )
    
    auth_service = AuthService(config)
    await auth_service.initialize()
    
    # Generate token
    token_request = TokenRequest(
        grant_type="password",
        subject="paseto-user",
        scope="profile email",
        audience="paseto-client"
    )
    
    try:
        token_response = await auth_service.generate_token(token_request)
        print(f"✓ PASETO Token generated: {token_response.access_token[:30]}...")
        
        # Validate token
        token_data = await auth_service.validate_token(token_response.access_token)
        if token_data:
            print(f"✓ PASETO token validated successfully")
            print(f"  Secure: PASETO tokens are tamper-proof")
        else:
            print("✗ PASETO token validation failed")
            
    except Exception as e:
        print(f"✗ PASETO demo failed: {e}")


async def demo_basic_auth():
    """Demonstrate Basic authentication."""
    print("\n=== Basic Authentication Demo ===")
    
    # Create Basic auth service
    config = AuthServiceConfig(
        auth_type=AuthType.BASIC,
        access_token_expiry=timedelta(minutes=15),
        extra_config={
            "valid_credentials": {
                "demo-user": "demo-password",
                "admin": "admin-secret"
            }
        }
    )
    
    auth_service = AuthService(config)
    await auth_service.initialize()
    
    # Generate token with basic credentials
    token_request = TokenRequest(
        grant_type="password",
        subject="demo-user",
        scope="basic:access",
        username="demo-user",
        password="demo-password"
    )
    
    try:
        token_response = await auth_service.generate_token(token_request)
        print(f"✓ Basic Auth Token generated: {token_response.access_token[:20]}...")
        
        # Validate token
        token_data = await auth_service.validate_token(token_response.access_token)
        if token_data:
            print(f"✓ Basic auth token validated successfully")
        else:
            print("✗ Basic auth token validation failed")
            
    except Exception as e:
        print(f"✗ Basic auth demo failed: {e}")


async def demo_service_stats():
    """Demonstrate service statistics."""
    print("\n=== Authentication Service Statistics ===")
    
    auth_service = create_auth_service(AuthType.JWT, secret_key="stats-demo-key")
    await auth_service.initialize()
    
    # Generate a few tokens
    for i in range(3):
        token_request = TokenRequest(
            grant_type="client_credentials",
            subject=f"user-{i}",
            scope="read"
        )
        await auth_service.generate_token(token_request)
    
    # Get stats
    stats = auth_service.get_service_stats()
    print(f"✓ Service Stats:")
    print(f"  Initialized: {stats['initialized']}")
    print(f"  Auth Type: {stats['auth_type']}")
    print(f"  Active Tokens: {stats['active_tokens']}")
    print(f"  Token Expiry (hours): {stats['token_expiry_hours']}")
    print(f"  Issuer: {stats['issuer']}")
    
    # Clean up expired tokens
    cleaned = await auth_service.cleanup_expired_tokens()
    print(f"✓ Cleaned up {cleaned} expired tokens")


async def main():
    """Run all authentication examples."""
    print("GAuth Authentication Examples")
    print("=" * 50)
    
    try:
        await demo_jwt_auth()
        await demo_oauth2_auth()
        await demo_paseto_auth()
        await demo_basic_auth()
        await demo_service_stats()
        
        print("\n✓ All authentication demos completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())