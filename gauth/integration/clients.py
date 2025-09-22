"""
Integration package for GAuth framework external system integration.

This package provides utilities and clients for integrating GAuth with external systems
including authentication providers, databases, message brokers, and other services.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class IntegrationConfig:
    """Configuration for external system integration."""
    provider: str
    endpoint: str
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 1
    auth_method: str = "none"
    credentials: Optional[Dict[str, str]] = None
    extra_config: Optional[Dict[str, Any]] = None


class IntegrationError(Exception):
    """Base exception for integration errors."""
    
    def __init__(self, message: str, provider: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.provider = provider
        self.error_code = error_code


class ConnectionError(IntegrationError):
    """Error when connection to external system fails."""
    pass


class AuthenticationError(IntegrationError):
    """Error when authentication with external system fails."""
    pass


class ExternalSystemClient(ABC):
    """Abstract base class for external system clients."""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to external system."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to external system."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if external system is healthy."""
        pass
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with external system."""
        pass


class DatabaseClient(ExternalSystemClient):
    """Client for database integration."""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.connection = None
    
    async def connect(self) -> bool:
        """Connect to database."""
        try:
            self.logger.info(f"Connecting to database: {self.config.endpoint}")
            # Simulate database connection
            await asyncio.sleep(0.1)
            self.connection = f"db_connection_{self.config.provider}"
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to database: {e}", self.config.provider)
    
    async def disconnect(self) -> None:
        """Disconnect from database."""
        if self.connection:
            self.logger.info("Disconnecting from database")
            self.connection = None
    
    async def health_check(self) -> bool:
        """Check database health."""
        if not self.connection:
            return False
        try:
            # Simulate health check query
            await asyncio.sleep(0.05)
            return True
        except Exception:
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with database."""
        if not self.config.credentials:
            return True  # No auth required
        
        try:
            # Simulate authentication
            await asyncio.sleep(0.1)
            return True
        except Exception as e:
            raise AuthenticationError(f"Database authentication failed: {e}", self.config.provider)
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute database query."""
        if not self.connection:
            raise ConnectionError("Not connected to database", self.config.provider)
        
        self.logger.debug(f"Executing query: {query}")
        # Simulate query execution
        await asyncio.sleep(0.1)
        return [{"result": "success", "query": query, "params": params}]


class RedisClient(ExternalSystemClient):
    """Client for Redis integration."""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.redis_client = None
    
    async def connect(self) -> bool:
        """Connect to Redis."""
        try:
            self.logger.info(f"Connecting to Redis: {self.config.endpoint}")
            # Simulate Redis connection
            await asyncio.sleep(0.1)
            self.redis_client = f"redis_client_{self.config.provider}"
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Redis: {e}", self.config.provider)
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis_client:
            self.logger.info("Disconnecting from Redis")
            self.redis_client = None
    
    async def health_check(self) -> bool:
        """Check Redis health."""
        if not self.redis_client:
            return False
        try:
            # Simulate ping
            await asyncio.sleep(0.05)
            return True
        except Exception:
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with Redis."""
        if not self.config.credentials:
            return True
        
        try:
            # Simulate Redis AUTH
            await asyncio.sleep(0.1)
            return True
        except Exception as e:
            raise AuthenticationError(f"Redis authentication failed: {e}", self.config.provider)
    
    async def set(self, key: str, value: str, expire: Optional[int] = None) -> bool:
        """Set value in Redis."""
        if not self.redis_client:
            raise ConnectionError("Not connected to Redis", self.config.provider)
        
        self.logger.debug(f"Setting Redis key: {key}")
        # Simulate Redis SET
        await asyncio.sleep(0.05)
        return True
    
    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis."""
        if not self.redis_client:
            raise ConnectionError("Not connected to Redis", self.config.provider)
        
        self.logger.debug(f"Getting Redis key: {key}")
        # Simulate Redis GET
        await asyncio.sleep(0.05)
        return f"value_for_{key}"
    
    async def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        if not self.redis_client:
            raise ConnectionError("Not connected to Redis", self.config.provider)
        
        self.logger.debug(f"Deleting Redis key: {key}")
        # Simulate Redis DEL
        await asyncio.sleep(0.05)
        return True


class HTTPClient(ExternalSystemClient):
    """Client for HTTP API integration."""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.session = None
        self.auth_headers = {}
    
    async def connect(self) -> bool:
        """Initialize HTTP client."""
        try:
            self.logger.info(f"Initializing HTTP client for: {self.config.endpoint}")
            # Simulate HTTP client initialization
            await asyncio.sleep(0.1)
            self.session = f"http_session_{self.config.provider}"
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to initialize HTTP client: {e}", self.config.provider)
    
    async def disconnect(self) -> None:
        """Close HTTP client."""
        if self.session:
            self.logger.info("Closing HTTP client")
            self.session = None
            self.auth_headers = {}
    
    async def health_check(self) -> bool:
        """Check HTTP endpoint health."""
        if not self.session:
            return False
        try:
            # Simulate health check request
            await asyncio.sleep(0.1)
            return True
        except Exception:
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with HTTP API."""
        if not self.config.credentials:
            return True
        
        try:
            # Simulate authentication request
            await asyncio.sleep(0.1)
            self.auth_headers = {"Authorization": "Bearer simulated_token"}
            return True
        except Exception as e:
            raise AuthenticationError(f"HTTP authentication failed: {e}", self.config.provider)
    
    async def request(self, method: str, path: str, 
                     data: Optional[Dict[str, Any]] = None,
                     headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make HTTP request."""
        if not self.session:
            raise ConnectionError("HTTP client not initialized", self.config.provider)
        
        # Merge auth headers
        request_headers = {**self.auth_headers}
        if headers:
            request_headers.update(headers)
        
        self.logger.debug(f"Making {method} request to {path}")
        # Simulate HTTP request
        await asyncio.sleep(0.1)
        
        return {
            "status": 200,
            "method": method,
            "path": path,
            "data": data,
            "headers": request_headers
        }


class MessageBrokerClient(ExternalSystemClient):
    """Client for message broker integration (RabbitMQ, Kafka, etc.)."""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.broker_client = None
    
    async def connect(self) -> bool:
        """Connect to message broker."""
        try:
            self.logger.info(f"Connecting to message broker: {self.config.endpoint}")
            # Simulate broker connection
            await asyncio.sleep(0.1)
            self.broker_client = f"broker_client_{self.config.provider}"
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to message broker: {e}", self.config.provider)
    
    async def disconnect(self) -> None:
        """Disconnect from message broker."""
        if self.broker_client:
            self.logger.info("Disconnecting from message broker")
            self.broker_client = None
    
    async def health_check(self) -> bool:
        """Check message broker health."""
        if not self.broker_client:
            return False
        try:
            # Simulate health check
            await asyncio.sleep(0.05)
            return True
        except Exception:
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with message broker."""
        if not self.config.credentials:
            return True
        
        try:
            # Simulate authentication
            await asyncio.sleep(0.1)
            return True
        except Exception as e:
            raise AuthenticationError(f"Message broker authentication failed: {e}", self.config.provider)
    
    async def publish(self, topic: str, message: Dict[str, Any]) -> bool:
        """Publish message to topic."""
        if not self.broker_client:
            raise ConnectionError("Not connected to message broker", self.config.provider)
        
        self.logger.debug(f"Publishing message to topic: {topic}")
        # Simulate message publishing
        await asyncio.sleep(0.05)
        return True
    
    async def subscribe(self, topic: str, callback) -> bool:
        """Subscribe to topic."""
        if not self.broker_client:
            raise ConnectionError("Not connected to message broker", self.config.provider)
        
        self.logger.debug(f"Subscribing to topic: {topic}")
        # Simulate subscription
        await asyncio.sleep(0.05)
        return True


class IntegrationManager:
    """Manages multiple external system integrations."""
    
    def __init__(self):
        self.clients: Dict[str, ExternalSystemClient] = {}
        self.logger = logging.getLogger(f"{__name__}.IntegrationManager")
    
    def register_client(self, name: str, client: ExternalSystemClient) -> None:
        """Register an external system client."""
        self.clients[name] = client
        self.logger.info(f"Registered integration client: {name}")
    
    def get_client(self, name: str) -> Optional[ExternalSystemClient]:
        """Get registered client by name."""
        return self.clients.get(name)
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect to all registered systems."""
        results = {}
        for name, client in self.clients.items():
            try:
                self.logger.info(f"Connecting to {name}")
                success = await client.connect()
                if success:
                    await client.authenticate()
                results[name] = success
            except Exception as e:
                self.logger.error(f"Failed to connect to {name}: {e}")
                results[name] = False
        
        return results
    
    async def disconnect_all(self) -> None:
        """Disconnect from all systems."""
        for name, client in self.clients.items():
            try:
                self.logger.info(f"Disconnecting from {name}")
                await client.disconnect()
            except Exception as e:
                self.logger.error(f"Failed to disconnect from {name}: {e}")
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all connected systems."""
        results = {}
        for name, client in self.clients.items():
            try:
                results[name] = await client.health_check()
            except Exception as e:
                self.logger.error(f"Health check failed for {name}: {e}")
                results[name] = False
        
        return results


# Factory functions for creating clients
def create_database_client(provider: str, endpoint: str, **kwargs) -> DatabaseClient:
    """Create database client."""
    config = IntegrationConfig(
        provider=provider,
        endpoint=endpoint,
        **kwargs
    )
    return DatabaseClient(config)


def create_redis_client(endpoint: str, **kwargs) -> RedisClient:
    """Create Redis client."""
    config = IntegrationConfig(
        provider="redis",
        endpoint=endpoint,
        **kwargs
    )
    return RedisClient(config)


def create_http_client(endpoint: str, **kwargs) -> HTTPClient:
    """Create HTTP client."""
    config = IntegrationConfig(
        provider="http",
        endpoint=endpoint,
        **kwargs
    )
    return HTTPClient(config)


def create_message_broker_client(provider: str, endpoint: str, **kwargs) -> MessageBrokerClient:
    """Create message broker client."""
    config = IntegrationConfig(
        provider=provider,
        endpoint=endpoint,
        **kwargs
    )
    return MessageBrokerClient(config)