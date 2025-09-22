"""
Validation utilities for GAuth framework.
Provides validation functions for common data types.
"""

import re
import uuid
import ipaddress
from typing import Optional
from urllib.parse import urlparse


def validate_email(email: str) -> bool:
    """Validate email address format."""
    if not email or not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url: str) -> bool:
    """Validate URL format."""
    if not url or not isinstance(url, str):
        return False
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_uuid(uuid_str: str) -> bool:
    """Validate UUID format."""
    if not uuid_str or not isinstance(uuid_str, str):
        return False
    
    try:
        uuid.UUID(uuid_str)
        return True
    except (ValueError, TypeError):
        return False


def validate_phone(phone: str) -> bool:
    """Validate phone number format (basic validation)."""
    if not phone or not isinstance(phone, str):
        return False
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\+\.]', '', phone)
    
    # Check if it's all digits and reasonable length
    return cleaned.isdigit() and 10 <= len(cleaned) <= 15


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format (IPv4 or IPv6)."""
    if not ip or not isinstance(ip, str):
        return False
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_identifier(identifier: str, min_length: int = 1, max_length: int = 255) -> bool:
    """
    Validate if a string is a valid identifier.
    Allows alphanumeric characters, underscores, and hyphens.
    """
    if not identifier or not isinstance(identifier, str):
        return False
    
    if not (min_length <= len(identifier) <= max_length):
        return False
    
    # Must start with alphanumeric character
    if not identifier[0].isalnum():
        return False
    
    # Can contain alphanumeric characters, underscores, and hyphens
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$'
    return bool(re.match(pattern, identifier))


def sanitize_string(text: str, max_length: Optional[int] = None, 
                   allow_html: bool = False) -> str:
    """
    Sanitize a string by removing/escaping potentially dangerous content.
    """
    if not isinstance(text, str):
        return ""
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Remove control characters except common whitespace
    text = ''.join(char for char in text 
                  if ord(char) >= 32 or char in '\t\n\r')
    
    # Escape HTML if not allowed
    if not allow_html:
        text = (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    # Truncate if max_length specified
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength and return issues.
    Returns (is_valid, list_of_issues).
    """
    issues = []
    
    if not password:
        return False, ["Password is required"]
    
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        issues.append("Password must be no more than 128 characters long")
    
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password must contain at least one special character")
    
    # Check for common patterns
    if re.search(r'(.)\1{2,}', password):
        issues.append("Password should not contain repeated characters")
    
    common_patterns = ['123', 'abc', 'password', 'admin', 'user']
    if any(pattern in password.lower() for pattern in common_patterns):
        issues.append("Password should not contain common patterns")
    
    return len(issues) == 0, issues


def validate_json_structure(data: dict, required_fields: list[str], 
                           optional_fields: Optional[list[str]] = None) -> tuple[bool, list[str]]:
    """
    Validate JSON structure has required fields and no unexpected fields.
    Returns (is_valid, list_of_issues).
    """
    issues = []
    
    if not isinstance(data, dict):
        return False, ["Data must be a JSON object"]
    
    # Check required fields
    for field in required_fields:
        if field not in data:
            issues.append(f"Missing required field: {field}")
    
    # Check for unexpected fields
    allowed_fields = set(required_fields)
    if optional_fields:
        allowed_fields.update(optional_fields)
    
    unexpected_fields = set(data.keys()) - allowed_fields
    if unexpected_fields:
        issues.append(f"Unexpected fields: {', '.join(unexpected_fields)}")
    
    return len(issues) == 0, issues


def validate_range(value: float, min_val: Optional[float] = None, 
                  max_val: Optional[float] = None) -> bool:
    """Validate that a numeric value is within a specified range."""
    if min_val is not None and value < min_val:
        return False
    
    if max_val is not None and value > max_val:
        return False
    
    return True


def validate_enum_value(value: str, allowed_values: list[str], 
                       case_sensitive: bool = True) -> bool:
    """Validate that a value is in the allowed enum values."""
    if not case_sensitive:
        value = value.lower()
        allowed_values = [v.lower() for v in allowed_values]
    
    return value in allowed_values


def normalize_string(text: str, lowercase: bool = True, 
                    remove_spaces: bool = False) -> str:
    """Normalize a string for comparison or storage."""
    if not isinstance(text, str):
        return ""
    
    # Strip whitespace
    text = text.strip()
    
    # Convert to lowercase if requested
    if lowercase:
        text = text.lower()
    
    # Remove spaces if requested
    if remove_spaces:
        text = text.replace(' ', '')
    
    # Normalize unicode
    import unicodedata
    text = unicodedata.normalize('NFKC', text)
    
    return text