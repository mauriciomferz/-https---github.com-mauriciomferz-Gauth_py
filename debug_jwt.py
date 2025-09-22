"""
Debug JWT timestamp issue.
"""
import sys
from datetime import datetime, timedelta

# Add current directory to path
sys.path.insert(0, '/Users/mauricio.fernandez_fernandezsiemens.co/Documents/GitHub/Repo/Gauth_py')

def test_timestamp_logic():
    """Test the timestamp logic used in JWT."""
    print("Testing timestamp logic...")
    
    now = datetime.utcnow()
    exp = now + timedelta(minutes=60)
    
    print(f"Current time (UTC): {now}")
    print(f"Expiry time (UTC): {exp}")
    print(f"Current timestamp: {int(now.timestamp())}")
    print(f"Expiry timestamp: {int(exp.timestamp())}")
    
    # Convert back to check
    exp_check = datetime.fromtimestamp(int(exp.timestamp()))
    print(f"Expiry converted back: {exp_check}")
    
    # Check if expired
    is_expired = exp_check < now
    print(f"Is expired?: {is_expired}")
    print(f"Time difference: {exp_check - now}")

def test_mock_jwt():
    """Test mock JWT behavior."""
    print("\nTesting mock JWT logic...")
    
    # Simulate mock JWT generation
    now = datetime.utcnow()
    exp = now + timedelta(minutes=60)
    
    claims = {
        'iss': 'gauth',
        'sub': 'test_user',
        'aud': None,
        'exp': int(exp.timestamp()),
        'iat': int(now.timestamp()),
        'jti': f"jwt_{int(now.timestamp())}"
    }
    
    print(f"Claims: {claims}")
    
    # Mock token (base64 encoded JSON)
    import json
    import base64
    
    # Create JWT-like structure (header.payload.signature)
    header = {"alg": "HS256", "typ": "JWT"}
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    signature = "mock_signature"
    
    mock_token = f"{header_b64}.{payload_b64}.{signature}"
    print(f"Mock token: {mock_token[:100]}...")
    
    # Now test decoding
    try:
        # Split token
        parts = mock_token.split('.')
        if len(parts) == 3:
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload_decoded = base64.urlsafe_b64decode(payload_padded)
            payload_json = json.loads(payload_decoded)
            
            print(f"Decoded payload: {payload_json}")
            
            # Check expiry
            exp_timestamp = payload_json.get('exp', 0)
            current_timestamp = int(datetime.utcnow().timestamp())
            
            print(f"Token exp timestamp: {exp_timestamp}")
            print(f"Current timestamp: {current_timestamp}")
            print(f"Is expired: {exp_timestamp < current_timestamp}")
            
    except Exception as e:
        print(f"Decode error: {e}")

if __name__ == "__main__":
    test_timestamp_logic()
    test_mock_jwt()