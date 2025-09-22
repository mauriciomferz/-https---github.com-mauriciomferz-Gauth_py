# GAuth Examples

This directory contains comprehensive examples demonstrating various features and capabilities of the GAuth Python implementation.

## Available Examples

### Core Features

- **[basic_usage.py](basic_usage.py)** - Basic GAuth usage patterns and fundamental operations
- **[advanced_features.py](advanced_features.py)** - Advanced GAuth features and complex scenarios
- **[poa_demo.py](poa_demo.py)** - RFC 115 Proof of Authority (PoA) implementation demonstration

### Authentication Examples

- **[auth/](auth/)** - Comprehensive authentication examples
  - JWT authentication and token management
  - OAuth2 flows and client credentials
  - PASETO secure token implementation
  - Basic authentication patterns
  - Authentication service statistics
  - Signing key rotation with grace validation (`auth/rotation_demo.py`)

### Rate Limiting Examples

- **[ratelimit/](ratelimit/)** - Rate limiting strategies and algorithms
  - Token bucket rate limiting with burst capacity
  - Sliding window rate limiting for precise control
  - Fixed window rate limiting for simple scenarios
  - Adaptive rate limiting that adjusts based on usage
  - Per-client rate limiting with automatic cleanup
  - Realistic traffic simulation

### Resilience Examples

- **[resilience/](resilience/)** - Resilience patterns and fault tolerance
  - Circuit breaker pattern for failure detection
  - Retry mechanisms with exponential backoff
  - Timeout handling and cancellation
  - Graceful degradation strategies
  - Combined resilience patterns

### Monitoring Examples

- **[monitoring/](monitoring/)** - Monitoring and observability
  - Metrics collection and reporting
  - Health checks and service monitoring
  - Performance monitoring and statistics
  - Audit logging and event tracking
  - Real-time dashboard simulation

## Running the Examples

### Prerequisites

Make sure you have the GAuth Python package installed:

```bash
pip install -e .
```

### Running Individual Examples

Execute any example directly:

```bash
# Basic usage
python examples/basic_usage.py

# Advanced features
python examples/advanced_features.py

# PoA demonstration
python examples/poa_demo.py

# Authentication examples
python examples/auth/main.py
# JWT signing key rotation demo (short intervals for illustrative purposes)
python examples/auth/rotation_demo.py

# Rate limiting examples  
python examples/ratelimit/main.py

# Resilience examples
python examples/resilience/main.py

# Monitoring examples
python examples/monitoring/main.py
```

### Running All Examples

You can run all examples in sequence (note: this will take several minutes):

```bash
# From the examples directory
for example in basic_usage.py advanced_features.py poa_demo.py auth/main.py ratelimit/main.py resilience/main.py monitoring/main.py; do
    echo "Running $example..."
    python "$example"
    echo "Completed $example"
    echo ""
done
```

## Example Categories

### 1. Basic Usage
Learn fundamental GAuth concepts including token generation, validation, and basic authentication flows.

### 2. Advanced Features
Explore sophisticated features like delegation, authorization policies, and complex authentication scenarios.

### 3. Proof of Authority (PoA)
Understand RFC 115 compliance with commercial enterprise, individual, and agentic AI proof of authority demonstrations.

### 4. Authentication
Deep dive into different authentication methods supported by GAuth, including JWT, OAuth2, PASETO, and Basic authentication.

### 5. Rate Limiting
Explore various rate limiting algorithms and strategies for protecting your APIs and services from abuse.

### 6. Resilience
Learn how to build fault-tolerant systems using circuit breakers, retries, timeouts, and graceful degradation.

### 7. Monitoring
Implement comprehensive monitoring solutions with metrics, health checks, performance tracking, and audit logging.

## Example Output

Each example provides detailed console output showing:
- ✓ Successful operations with relevant details
- ✗ Failed operations with error information
- 📊 Statistics and metrics where applicable
- 🚨 Security alerts and important notifications
- ℹ️ Informational messages and explanations

## Integration with GAuth Components

These examples demonstrate integration with all major GAuth components:

- **Authentication**: JWT, OAuth2, PASETO, Basic auth managers
- **Authorization**: Policy-based access control and delegation
- **Rate Limiting**: Multiple algorithms and per-client limiting
- **Circuit Breaking**: Failure detection and recovery
- **Monitoring**: Metrics, health checks, and audit logging
- **Events**: Event bus and handler patterns
- **Storage**: Token stores and persistence layers
- **Utilities**: Common functions and helper methods

## Extending the Examples

Feel free to modify and extend these examples for your specific use cases. The examples are designed to be:

- **Modular**: Each example can be run independently
- **Educational**: Well-commented code with clear explanations
- **Practical**: Real-world scenarios and patterns
- **Extensible**: Easy to modify and adapt

## Contributing

If you create additional examples or improvements, please consider contributing them back to the project. Examples should:

1. Focus on a specific feature or use case
2. Include clear documentation and comments
3. Provide meaningful output and error handling
4. Follow the existing code style and patterns

For more information about GAuth features and capabilities, see the main project documentation.