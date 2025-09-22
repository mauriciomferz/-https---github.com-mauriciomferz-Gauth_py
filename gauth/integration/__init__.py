# Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
# All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
# See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
# Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.

"""
Integration package for GAuth framework external system integration and testing.

This package provides:
- External system integration clients (Database, Redis, HTTP, Message Brokers)
- Integration testing utilities and test runners
- Mock services for testing
- Test environment management

Protocol Usage Declaration:
  - GAuth protocol: IMPLEMENTED throughout this package (see [GAuth] comments)
  - OAuth 2.0:      NOT USED anywhere in this package
  - PKCE:           NOT USED anywhere in this package
  - OpenID:         NOT USED anywhere in this package
"""

from .clients import (
    # Configuration and errors
    IntegrationConfig, IntegrationError, ConnectionError, AuthenticationError,
    
    # Base client
    ExternalSystemClient,
    
    # Specific clients
    DatabaseClient, RedisClient, HTTPClient, MessageBrokerClient,
    
    # Management
    IntegrationManager,
    
    # Factory functions
    create_database_client, create_redis_client, 
    create_http_client, create_message_broker_client
)

from .testing import (
    # Test configuration and results
    TestConfig, TestResult,
    
    # Mock services
    MockExternalService,
    
    # Test environment
    TestEnvironment, IntegrationTestRunner,
    
    # Utility functions
    create_test_gauth_instance, create_test_token_store, assert_test_result
)

__all__ = [
    # Configuration and errors
    'IntegrationConfig', 'IntegrationError', 'ConnectionError', 'AuthenticationError',
    
    # Base client
    'ExternalSystemClient',
    
    # Specific clients
    'DatabaseClient', 'RedisClient', 'HTTPClient', 'MessageBrokerClient',
    
    # Management
    'IntegrationManager',
    
    # Factory functions
    'create_database_client', 'create_redis_client',
    'create_http_client', 'create_message_broker_client',
    
    # Test configuration and results
    'TestConfig', 'TestResult',
    
    # Mock services
    'MockExternalService',
    
    # Test environment
    'TestEnvironment', 'IntegrationTestRunner',
    
    # Utility functions
    'create_test_gauth_instance', 'create_test_token_store', 'assert_test_result'
]