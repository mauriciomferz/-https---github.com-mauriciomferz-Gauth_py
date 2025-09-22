"""
Configuration module for GAuth Python implementation.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.
"""

from datetime import timedelta
from typing import List, Optional
from dataclasses import dataclass, field
import os


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    max_requests: int = 100
    time_window: timedelta = field(default_factory=lambda: timedelta(minutes=1))
    burst_limit: int = 10


@dataclass
class TokenConfig:
    """Token configuration settings"""
    algorithm: str = "HS256"
    secret_key: str = ""
    issuer: str = "gauth-py"
    audience: str = "gauth-client"
    
    def __post_init__(self):
        if not self.secret_key:
            # Try to get from environment variable
            self.secret_key = os.getenv("GAUTH_SECRET_KEY", "default-secret-key")


@dataclass
class Config:
    """Configuration for GAuth protocol implementation"""
    auth_server_url: str
    client_id: str
    client_secret: str
    scopes: List[str] = field(default_factory=list)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    access_token_expiry: timedelta = field(default_factory=lambda: timedelta(hours=1))
    token_config: Optional[TokenConfig] = None

    def __post_init__(self):
        if self.token_config is None:
            self.token_config = TokenConfig(secret_key=self.client_secret)

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables"""
        return cls(
            auth_server_url=os.getenv("GAUTH_AUTH_SERVER_URL", "https://auth.example.com"),
            client_id=os.getenv("GAUTH_CLIENT_ID", ""),
            client_secret=os.getenv("GAUTH_CLIENT_SECRET", ""),
            scopes=os.getenv("GAUTH_SCOPES", "read,write").split(","),
            access_token_expiry=timedelta(
                hours=int(os.getenv("GAUTH_TOKEN_EXPIRY_HOURS", "1"))
            ),
        )

    def validate(self) -> bool:
        """Validate the configuration"""
        if not self.auth_server_url:
            raise ValueError("auth_server_url is required")
        if not self.client_id:
            raise ValueError("client_id is required")
        if not self.client_secret:
            raise ValueError("client_secret is required")
        return True