"""
Simple test to debug the auth package issues.
"""
import asyncio
import sys
import os

# Add current directory to path
sys.path.insert(0, '/Users/mauricio.fernandez_fernandezsiemens.co/Documents/GitHub/Repo/Gauth_py')

from gauth.auth import AuthType, AuthConfig, TokenRequest, GAuthAuthenticator

async def test_basic_auth():
    """Test basic authentication functionality."""
    print("Testing basic auth functionality...")
    
    # Create config
    config = AuthConfig(
        auth_type=AuthType.JWT,
        extra_config={'secret_key': 'test_secret'}
    )
    print(f"Config created: {config}")
    
    # Create authenticator
    authenticator = GAuthAuthenticator(config)
    print(f"Authenticator created: {authenticator}")
    
    try:
        # Initialize
        await authenticator.initialize()
        print("Authenticator initialized successfully")
        
        # Create token request
        request = TokenRequest(
            grant_type="client_credentials",
            subject="test_user"
        )
        print(f"Token request: {request}")
        
        # Generate token
        response = await authenticator.generate_token(request)
        print(f"Token response: {response}")
        print(f"Access token: {response.access_token}")
        
        # Validate token
        validation_result = await authenticator.validate_token(response.access_token)
        print(f"Validation result: {validation_result}")
        print(f"Valid: {validation_result.valid}")
        print(f"Error: {validation_result.error}")
        
        if validation_result.token_data:
            print(f"Token data subject: {validation_result.token_data.subject}")
        
        await authenticator.close()
        print("Test completed successfully")
        
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_basic_auth())