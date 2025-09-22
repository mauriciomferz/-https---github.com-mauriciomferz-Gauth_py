"""
Common utilities and helper functions for GAuth framework.
"""

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


def generate_id(prefix: str = "") -> str:
    """Generate a unique identifier with optional prefix."""
    unique_id = str(uuid.uuid4())
    return f"{prefix}{unique_id}" if prefix else unique_id


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def generate_request_id() -> str:
    """Generate a request ID for tracing."""
    return f"req_{int(time.time())}_{secrets.token_hex(8)}"


def generate_correlation_id() -> str:
    """Generate a correlation ID for distributed tracing."""
    return f"corr_{secrets.token_hex(16)}"


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """
    Hash a string using the specified algorithm.
    
    Args:
        data: String to hash
        algorithm: Hash algorithm (sha256, sha512, md5)
        
    Returns:
        Hexadecimal hash string
    """
    if algorithm == "sha256":
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data.encode('utf-8')).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def safe_dict_get(dictionary: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Safely get a value from a dictionary with optional default."""
    return dictionary.get(key, default)


def safe_list_get(lst: List[Any], index: int, default: Any = None) -> Any:
    """Safely get an item from a list with optional default."""
    try:
        return lst[index]
    except (IndexError, TypeError):
        return default


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten a nested dictionary.
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for nested keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def merge_dicts(*dicts: Dict[str, Any], deep: bool = False) -> Dict[str, Any]:
    """
    Merge multiple dictionaries.
    
    Args:
        *dicts: Dictionaries to merge
        deep: Whether to perform deep merge for nested dictionaries
        
    Returns:
        Merged dictionary
    """
    result = {}
    
    for d in dicts:
        if not isinstance(d, dict):
            continue
            
        for key, value in d.items():
            if deep and key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_dicts(result[key], value, deep=True)
            else:
                result[key] = value
                
    return result


def sanitize_dict(data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Sanitize a dictionary by masking sensitive values.
    
    Args:
        data: Dictionary to sanitize
        sensitive_keys: List of keys to mask (default: common sensitive keys)
        
    Returns:
        Sanitized dictionary
    """
    if sensitive_keys is None:
        sensitive_keys = [
            'password', 'secret', 'token', 'key', 'auth', 'credential',
            'api_key', 'access_token', 'refresh_token', 'client_secret'
        ]
    
    sanitized = {}
    for key, value in data.items():
        lower_key = key.lower()
        if any(sensitive in lower_key for sensitive in sensitive_keys):
            if isinstance(value, str) and len(value) > 4:
                sanitized[key] = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                sanitized[key] = '***'
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, sensitive_keys)
        else:
            sanitized[key] = value
            
    return sanitized


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def normalize_url(url: str) -> str:
    """
    Normalize a URL by removing trailing slashes and converting to lowercase.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    if not url:
        return url
        
    # Remove trailing slash
    normalized = url.rstrip('/')
    
    # Convert scheme and host to lowercase
    if '://' in normalized:
        scheme_host, path = normalized.split('://', 1)
        if '/' in path:
            host, path_part = path.split('/', 1)
            normalized = f"{scheme_host.lower()}://{host.lower()}/{path_part}"
        else:
            normalized = f"{scheme_host.lower()}://{path.lower()}"
    
    return normalized


def get_current_timestamp() -> int:
    """Get current timestamp in seconds since epoch."""
    return int(time.time())


def get_current_iso_timestamp() -> str:
    """Get current timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string to datetime.
    
    Args:
        timestamp_str: ISO 8601 timestamp string
        
    Returns:
        Parsed datetime object
    """
    return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))


def is_expired(expiry_time: Union[int, datetime], grace_period: int = 0) -> bool:
    """
    Check if a timestamp has expired.
    
    Args:
        expiry_time: Expiry time as timestamp or datetime
        grace_period: Grace period in seconds
        
    Returns:
        True if expired, False otherwise
    """
    current_time = datetime.now(timezone.utc)
    
    if isinstance(expiry_time, int):
        expiry_dt = datetime.fromtimestamp(expiry_time, tz=timezone.utc)
    else:
        expiry_dt = expiry_time
    
    # Add grace period
    if grace_period > 0:
        from datetime import timedelta
        expiry_dt += timedelta(seconds=grace_period)
    
    return current_time > expiry_dt


def format_duration(seconds: Union[int, float]) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        return f"{minutes}m{remaining_seconds}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h{remaining_minutes}m"


def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> List[str]:
    """
    Validate that required fields are present in data.
    
    Args:
        data: Data dictionary to validate
        required_fields: List of required field names
        
    Returns:
        List of missing field names
    """
    missing_fields = []
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == "":
            missing_fields.append(field)
    return missing_fields


def deep_copy_dict(original: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a deep copy of a dictionary.
    
    Args:
        original: Original dictionary
        
    Returns:
        Deep copy of the dictionary
    """
    import copy
    return copy.deepcopy(original)


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """
    Mask sensitive data, showing only first and last few characters.
    
    Args:
        data: Data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Masked string
    """
    if len(data) <= visible_chars * 2:
        return mask_char * len(data)
    
    visible_start = visible_chars // 2
    visible_end = visible_chars - visible_start
    
    masked_length = len(data) - visible_chars
    return data[:visible_start] + mask_char * masked_length + data[-visible_end:]


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]