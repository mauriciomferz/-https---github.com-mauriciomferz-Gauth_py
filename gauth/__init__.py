"""
GAuth Python Package

AI Power-of-Attorney Authorization Framework - Python Implementation
"""

__version__ = "0.1.0"
__author__ = "Mauricio Fernandez"
__email__ = "mauricio.fernandez@siemens.com"

from .core.gauth import GAuth
from .core.config import Config
from .core.types import (
    AuthorizationRequest,
    AuthorizationGrant,
    AccessToken,
    Transaction,
    TransactionResult,
)

__all__ = [
    "GAuth",
    "Config", 
    "AuthorizationRequest",
    "AuthorizationGrant",
    "AccessToken", 
    "Transaction",
    "TransactionResult",
]