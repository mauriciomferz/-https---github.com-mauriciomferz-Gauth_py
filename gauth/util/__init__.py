# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Utility package providing common helper functions and classes for GAuth framework.

This package includes:
- Time range utilities for handling time periods and overlap detection
- Validation utilities for emails, URLs, UUIDs, and other data types
- Encoding/decoding utilities for base64, JSON, JWT, and secure operations
- Configuration management utilities for loading and validating settings

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package
"""

from .time_range import TimeRange, TimeOfDay, BusinessHours
from .validation import (
    validate_email, validate_url, validate_uuid, validate_phone_number,
    check_password_strength, PasswordStrength, validate_json_structure,
    validate_port_number, validate_ip_address, validate_domain_name,
    sanitize_string, validate_api_key, ValidationError
)
from .encoding import (
    encode_base64, decode_base64, encode_base64_url_safe,
    decode_base64_url_safe, encode_hex, decode_hex, encode_json,
    decode_json, extract_jwt_payload, create_secure_hash,
    compare_secure_strings, url_encode, url_decode, html_escape,
    html_unescape, EncodingError
)
from .config import (
    load_config_from_env, get_config_value, parse_duration_string,
    merge_configs, validate_config, normalize_config_key,
    expand_config_variables, create_default_config, load_config_file,
    save_config_file, get_bool_config, get_int_config, get_float_config,
    get_list_config
)

__all__ = [
    # Time range utilities
    'TimeRange', 'TimeOfDay', 'BusinessHours',
    
    # Validation utilities
    'validate_email', 'validate_url', 'validate_uuid', 'validate_phone_number',
    'check_password_strength', 'PasswordStrength', 'validate_json_structure',
    'validate_port_number', 'validate_ip_address', 'validate_domain_name',
    'sanitize_string', 'validate_api_key', 'ValidationError',
    
    # Encoding utilities
    'encode_base64', 'decode_base64', 'encode_base64_url_safe',
    'decode_base64_url_safe', 'encode_hex', 'decode_hex', 'encode_json',
    'decode_json', 'extract_jwt_payload', 'create_secure_hash',
    'compare_secure_strings', 'url_encode', 'url_decode', 'html_escape',
    'html_unescape', 'EncodingError',
    
    # Configuration utilities
    'load_config_from_env', 'get_config_value', 'parse_duration_string',
    'merge_configs', 'validate_config', 'normalize_config_key',
    'expand_config_variables', 'create_default_config', 'load_config_file',
    'save_config_file', 'get_bool_config', 'get_int_config', 'get_float_config',
    'get_list_config'
]