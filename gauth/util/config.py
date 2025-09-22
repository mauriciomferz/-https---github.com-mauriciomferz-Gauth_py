"""
Configuration utilities for GAuth framework.
Provides configuration loading, validation, and management functions.
"""

import os
import re
from datetime import timedelta
from typing import Any, Dict, Optional, Union, List


def load_config_from_env(prefix: str = "GAUTH_") -> Dict[str, str]:
    """
    Load configuration from environment variables with given prefix.
    """
    config = {}
    
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Remove prefix and convert to lowercase
            config_key = key[len(prefix):].lower()
            config[config_key] = value
    
    return config


def get_config_value(key: str, default: Any = None, 
                    cast_type: Optional[type] = None,
                    env_prefix: str = "GAUTH_") -> Any:
    """
    Get configuration value from environment or return default.
    Optionally cast to specified type.
    """
    env_key = f"{env_prefix}{key.upper()}"
    value = os.environ.get(env_key, default)
    
    if value is None or cast_type is None:
        return value
    
    try:
        if cast_type == bool:
            # Handle boolean conversion specially
            if isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            return bool(value)
        elif cast_type == list:
            # Handle list conversion (comma-separated)
            if isinstance(value, str):
                return [item.strip() for item in value.split(',') if item.strip()]
            return list(value) if value else []
        else:
            return cast_type(value)
    except (ValueError, TypeError):
        return default


def parse_duration_string(duration_str: str) -> timedelta:
    """
    Parse duration string like '30s', '5m', '2h', '1d' into timedelta.
    """
    if not isinstance(duration_str, str):
        raise ValueError("Duration must be a string")
    
    duration_str = duration_str.strip().lower()
    
    # Pattern to match number followed by unit
    pattern = r'^(\d+(?:\.\d+)?)\s*([smhd])$'
    match = re.match(pattern, duration_str)
    
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")
    
    value, unit = match.groups()
    value = float(value)
    
    if unit == 's':
        return timedelta(seconds=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    else:
        raise ValueError(f"Unsupported duration unit: {unit}")


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple configuration dictionaries.
    Later configs override earlier ones.
    """
    result = {}
    
    for config in configs:
        if isinstance(config, dict):
            result.update(config)
    
    return result


def validate_config(config: Dict[str, Any], 
                   schema: Dict[str, Dict[str, Any]]) -> List[str]:
    """
    Validate configuration against a schema.
    Returns list of validation errors.
    
    Schema format:
    {
        'field_name': {
            'required': True/False,
            'type': type,
            'default': value,
            'choices': [list_of_valid_values],
            'min': min_value,
            'max': max_value
        }
    }
    """
    errors = []
    
    # Check required fields
    for field, rules in schema.items():
        if rules.get('required', False) and field not in config:
            errors.append(f"Missing required field: {field}")
            continue
        
        if field not in config:
            continue
        
        value = config[field]
        
        # Type validation
        expected_type = rules.get('type')
        if expected_type and not isinstance(value, expected_type):
            errors.append(f"Field {field} must be of type {expected_type.__name__}")
            continue
        
        # Choice validation
        choices = rules.get('choices')
        if choices and value not in choices:
            errors.append(f"Field {field} must be one of: {choices}")
        
        # Range validation for numeric types
        if isinstance(value, (int, float)):
            min_val = rules.get('min')
            max_val = rules.get('max')
            
            if min_val is not None and value < min_val:
                errors.append(f"Field {field} must be >= {min_val}")
            
            if max_val is not None and value > max_val:
                errors.append(f"Field {field} must be <= {max_val}")
    
    return errors


def normalize_config_key(key: str) -> str:
    """Normalize configuration key to standard format."""
    # Convert to lowercase and replace hyphens with underscores
    return key.lower().replace('-', '_')


def expand_config_variables(config: Dict[str, Any], 
                           variables: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Expand variables in configuration values.
    Variables are specified as ${VAR_NAME} in config values.
    """
    if variables is None:
        variables = dict(os.environ)
    
    def expand_value(value: Any) -> Any:
        if isinstance(value, str):
            # Find all variables in the string
            pattern = r'\$\{([^}]+)\}'
            
            def replace_var(match):
                var_name = match.group(1)
                return variables.get(var_name, match.group(0))
            
            return re.sub(pattern, replace_var, value)
        elif isinstance(value, dict):
            return {k: expand_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [expand_value(item) for item in value]
        else:
            return value
    
    return expand_value(config)


def create_default_config() -> Dict[str, Any]:
    """Create default configuration for GAuth."""
    return {
        'debug': False,
        'log_level': 'INFO',
        'host': '0.0.0.0',
        'port': 8080,
        'timeout': '30s',
        'max_connections': 1000,
        'rate_limit': {
            'enabled': True,
            'requests_per_second': 100,
            'burst_size': 20
        },
        'circuit_breaker': {
            'enabled': True,
            'error_threshold': 10,
            'reset_timeout': '30s'
        },
        'auth': {
            'jwt_secret': None,  # Must be provided
            'token_expiry': '1h',
            'refresh_token_expiry': '24h'
        },
        'monitoring': {
            'enabled': True,
            'metrics_port': 9090,
            'health_check_interval': '30s'
        }
    }


def load_config_file(file_path: str) -> Dict[str, Any]:
    """Load configuration from a file (JSON or YAML)."""
    import json
    from pathlib import Path
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    file_ext = Path(file_path).suffix.lower()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        if file_ext in ['.json']:
            return json.load(f)
        elif file_ext in ['.yaml', '.yml']:
            try:
                import yaml
                return yaml.safe_load(f)
            except ImportError:
                raise ImportError("PyYAML is required to load YAML configuration files")
        else:
            raise ValueError(f"Unsupported configuration file format: {file_ext}")


def save_config_file(config: Dict[str, Any], file_path: str, 
                    format_type: Optional[str] = None) -> None:
    """Save configuration to a file."""
    import json
    from pathlib import Path
    
    if format_type is None:
        format_type = Path(file_path).suffix.lower().lstrip('.')
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        if format_type == 'json':
            json.dump(config, f, indent=2, separators=(',', ': '))
        elif format_type in ['yaml', 'yml']:
            try:
                import yaml
                yaml.safe_dump(config, f, default_flow_style=False, indent=2)
            except ImportError:
                raise ImportError("PyYAML is required to save YAML configuration files")
        else:
            raise ValueError(f"Unsupported configuration format: {format_type}")


def get_bool_config(key: str, default: bool = False, 
                   env_prefix: str = "GAUTH_") -> bool:
    """Get boolean configuration value."""
    return get_config_value(key, default, bool, env_prefix)


def get_int_config(key: str, default: int = 0, 
                  env_prefix: str = "GAUTH_") -> int:
    """Get integer configuration value."""
    return get_config_value(key, default, int, env_prefix)


def get_float_config(key: str, default: float = 0.0, 
                    env_prefix: str = "GAUTH_") -> float:
    """Get float configuration value."""
    return get_config_value(key, default, float, env_prefix)


def get_list_config(key: str, default: Optional[List[str]] = None, 
                   env_prefix: str = "GAUTH_") -> List[str]:
    """Get list configuration value (comma-separated)."""
    if default is None:
        default = []
    return get_config_value(key, default, list, env_prefix)