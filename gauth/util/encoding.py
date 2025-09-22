"""
Encoding and decoding utilities for GAuth framework.
Provides safe encoding/decoding functions for various formats.
"""

import base64
import json
import binascii
from typing import Any, Optional, Dict, Union


def base64_encode(data: Union[str, bytes]) -> str:
    """Encode data to base64 string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return base64.b64encode(data).decode('ascii')


def base64_decode(encoded: str) -> bytes:
    """Decode base64 string to bytes."""
    try:
        return base64.b64decode(encoded)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid base64 data: {e}")


def url_safe_encode(data: Union[str, bytes]) -> str:
    """Encode data to URL-safe base64 string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def url_safe_decode(encoded: str) -> bytes:
    """Decode URL-safe base64 string to bytes."""
    # Add padding if needed
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += '=' * padding
    
    try:
        return base64.urlsafe_b64decode(encoded)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid URL-safe base64 data: {e}")


def hex_encode(data: Union[str, bytes]) -> str:
    """Encode data to hexadecimal string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return data.hex()


def hex_decode(encoded: str) -> bytes:
    """Decode hexadecimal string to bytes."""
    try:
        return bytes.fromhex(encoded)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal data: {e}")


def safe_json_encode(data: Any, pretty: bool = False) -> str:
    """
    Safely encode data to JSON string.
    Handles non-serializable objects gracefully.
    """
    def json_serializer(obj):
        """Custom serializer for non-standard types."""
        if hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):  # custom objects
            return obj.__dict__
        elif hasattr(obj, '_asdict'):  # namedtuples
            return obj._asdict()
        else:
            return str(obj)
    
    try:
        if pretty:
            return json.dumps(data, indent=2, separators=(',', ': '), 
                            default=json_serializer, ensure_ascii=False)
        else:
            return json.dumps(data, default=json_serializer, 
                            separators=(',', ':'), ensure_ascii=False)
    except Exception as e:
        raise ValueError(f"Failed to encode JSON: {e}")


def safe_json_decode(json_str: str, default: Any = None) -> Any:
    """
    Safely decode JSON string to Python object.
    Returns default value if decoding fails.
    """
    if not isinstance(json_str, str):
        return default
    
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return default


def encode_query_params(params: Dict[str, Any]) -> str:
    """Encode dictionary as URL query parameters."""
    from urllib.parse import urlencode, quote_plus
    
    # Convert all values to strings and handle None
    clean_params = {}
    for key, value in params.items():
        if value is not None:
            if isinstance(value, (list, tuple)):
                clean_params[key] = ','.join(str(v) for v in value)
            else:
                clean_params[key] = str(value)
    
    return urlencode(clean_params, quote_via=quote_plus)


def decode_query_params(query_string: str) -> Dict[str, str]:
    """Decode URL query parameters to dictionary."""
    from urllib.parse import parse_qs, unquote_plus
    
    if not query_string:
        return {}
    
    # Remove leading '?' if present
    if query_string.startswith('?'):
        query_string = query_string[1:]
    
    try:
        parsed = parse_qs(query_string, keep_blank_values=True)
        # Convert lists to single values (take first value)
        return {key: values[0] if values else '' 
                for key, values in parsed.items()}
    except Exception:
        return {}


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not isinstance(text, str):
        return str(text)
    
    return (text.replace('&', '&amp;')
               .replace('<', '&lt;')
               .replace('>', '&gt;')
               .replace('"', '&quot;')
               .replace("'", '&#x27;')
               .replace('/', '&#x2F;'))


def unescape_html(text: str) -> str:
    """Unescape HTML special characters."""
    if not isinstance(text, str):
        return str(text)
    
    return (text.replace('&amp;', '&')
               .replace('&lt;', '<')
               .replace('&gt;', '>')
               .replace('&quot;', '"')
               .replace('&#x27;', "'")
               .replace('&#x2F;', '/'))


def encode_jwt_payload(payload: Dict[str, Any]) -> str:
    """Encode JWT payload (base64url without padding)."""
    json_str = safe_json_encode(payload)
    return url_safe_encode(json_str)


def decode_jwt_payload(encoded_payload: str) -> Optional[Dict[str, Any]]:
    """Decode JWT payload from base64url encoding."""
    try:
        decoded_bytes = url_safe_decode(encoded_payload)
        json_str = decoded_bytes.decode('utf-8')
        return safe_json_decode(json_str)
    except Exception:
        return None


def secure_compare(a: str, b: str) -> bool:
    """
    Timing-safe string comparison to prevent timing attacks.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    
    # Ensure both strings have the same length for comparison
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0


def mask_sensitive_data(data: str, mask_char: str = '*', 
                       show_first: int = 2, show_last: int = 2) -> str:
    """
    Mask sensitive data leaving only first and last characters visible.
    """
    if not isinstance(data, str) or len(data) <= (show_first + show_last):
        return mask_char * len(data) if data else ""
    
    first_part = data[:show_first]
    last_part = data[-show_last:] if show_last > 0 else ""
    middle_length = len(data) - show_first - show_last
    
    return first_part + (mask_char * middle_length) + last_part


def generate_random_string(length: int = 32, 
                          alphabet: Optional[str] = None) -> str:
    """Generate a cryptographically secure random string."""
    import secrets
    import string
    
    if alphabet is None:
        alphabet = string.ascii_letters + string.digits
    
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_random_bytes(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes."""
    import secrets
    return secrets.token_bytes(length)