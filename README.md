[![Python CI](https://github.com/mauriciomferz/Gauth_py/actions/workflows/python-ci.yml/badge.svg)](https://github.com/mauriciomferz/Gauth_py/actions/workflows/python-ci.yml) [![Coverage](https://codecov.io/gh/mauriciomferz/Gauth_py/branch/main/graph/badge.svg)](https://codecov.io/gh/mauriciomferz/Gauth_py) [![PyPI version](https://badge.fury.io/py/gauth-py.svg)](https://badge.fury.io/py/gauth-py)

# GAuth: AI Power-of-Attorney Authorization Framework - Python Implementation

GAuth enables AI systems to act on behalf of humans or organizations, with explicit, verifiable, and auditable power-of-attorney flows. Built on OAuth, OpenID Connect, and MCP, GAuth is designed for open source, extensibility, and compliance with RFC 111 and RFC 115.

This is the **Python implementation** of the GAuth protocol, converted from the original Go implementation.

---

## Who is this for?
- Python developers integrating AI with sensitive actions or decisions
- Security architects and compliance teams working with Python stacks
- Organizations implementing structured AI authority delegation in Python environments
- Developers needing transparent, auditable AI authorization in async Python applications

## Quick Start

### Installation

```bash
# Install from PyPI (when published)
pip install gauth-py

# Or install from source
git clone https://github.com/mauriciomferz/Gauth_py.git
cd Gauth_py
pip install -e .
```

### Basic Usage

```python
import asyncio
from gauth import GAuth, Config
from gauth.core.types import AuthorizationRequest, TokenRequest, Transaction

async def main():
    # Create configuration
    config = Config(
        auth_server_url="https://auth.example.com",
        client_id="my-client",
        client_secret="my-secret",
        scopes=["read", "write"]
    )
    
    # Create GAuth instance
    gauth = GAuth.new(config)
    
    try:
        # Request authorization
        auth_request = AuthorizationRequest(
            client_id="my-client",
            scopes=["read"]
        )
        grant = await gauth.initiate_authorization(auth_request)
        
        # Request token
        token_request = TokenRequest(
            grant_id=grant.grant_id,
            scope=["read"],
            client_id="my-client"
        )
        token_response = await gauth.request_token(token_request)
        
        # Process transaction
        transaction = Transaction(
            client_id="my-client",
            action="read_data",
            resource="/api/data",
            scope_required=["read"]
        )
        result = await gauth.process_transaction(transaction, token_response.token)
        
        print(f"Transaction successful: {result.success}")
        
    finally:
        await gauth.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Run the Demo

```bash
python -m gauth.demo.main
```

## Key Features

### 🔐 **Authorization & Authentication**
- **Power-of-Attorney flows**: Explicit delegation and authorization
- **Token-based access**: Secure, time-limited access tokens
- **Scope-based permissions**: Fine-grained access control
- **Async/await support**: Full asynchronous operation support

### 📊 **Auditability & Compliance**
- **Comprehensive audit logging**: Every action is logged and traceable
- **RFC 111 & RFC 115 compliance**: Standards-compliant implementation
- **Configurable audit backends**: Memory, file, or custom storage
- **Audit event filtering**: Query audit logs by client, type, time range

### 🚀 **Performance & Scalability**
- **Rate limiting**: Configurable request rate limiting
- **Distributed storage**: Redis support for tokens and rate limiting
- **In-memory defaults**: Fast development and testing
- **Async operations**: Non-blocking I/O for high performance

### 🔧 **Developer Experience**
- **Type hints**: Full type annotation support
- **Async/await**: Modern Python async patterns
- **Comprehensive examples**: Multiple usage scenarios
- **Extensive testing**: High test coverage
- **Docker support**: Ready-to-use containers

## Architecture

```
gauth/
├── core/           # Core GAuth implementation
│   ├── gauth.py   # Main GAuth class
│   ├── config.py  # Configuration management
│   └── types.py   # Type definitions
├── audit/          # Audit logging
│   └── logger.py  # Audit logger implementations
├── token/          # Token storage
│   └── store.py   # Token store implementations
├── ratelimit/      # Rate limiting
│   └── limiter.py # Rate limiter implementations
└── demo/           # Demo application
    └── main.py    # Demo script
```

## RFC Compliance
- **RFC 111**: GiFo-RfC 0111 (GAuth) standard for AI power-of-attorney, delegation, and auditability
- **RFC 115**: GiFo-RfC 0115 (PoA) Power-of-Attorney credential definition for structured AI authority delegation
- All protocol roles, flows, and exclusions are respected. See https://gimelfoundation.com for full RFCs.

## Examples

### Basic Authorization Flow
```python
# See examples/basic_usage.py
python examples/basic_usage.py
```

### Advanced Features
```python
# See examples/advanced_features.py  
python examples/advanced_features.py
```

### With Redis and PostgreSQL
```python
# Using docker-compose
docker-compose up gauth-py-full
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/mauriciomferz/Gauth_py.git
cd Gauth_py

# Install in development mode
make install-dev

# Run tests
make test

# Run linting and formatting
make verify

# Run examples
make examples

# Run demo
make demo
```

### Docker Development

```bash
# Build and run with Docker
make docker-build
make docker-run

# Or use docker-compose
docker-compose up gauth-py-dev
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test file
python -m pytest tests/test_gauth_basic.py -v
```

## Configuration

### Environment Variables

```bash
GAUTH_CLIENT_ID=your-client-id
GAUTH_CLIENT_SECRET=your-client-secret
GAUTH_AUTH_SERVER_URL=https://auth.example.com
GAUTH_SECRET_KEY=your-secret-key
GAUTH_TOKEN_EXPIRY_HOURS=1
```

### Programmatic Configuration

```python
from gauth import Config
from datetime import timedelta

config = Config(
    auth_server_url="https://auth.example.com",
    client_id="my-client",
    client_secret="my-secret",
    scopes=["read", "write"],
    access_token_expiry=timedelta(hours=2)
)

# Or from environment
config = Config.from_env()
```

## Advanced Usage

### Custom Audit Logger

```python
from gauth.audit.logger import FileAuditLogger

audit_logger = FileAuditLogger("audit.log")
gauth = GAuth.new(config, audit_logger=audit_logger)
```

### Redis Token Store

```python
import redis.asyncio as redis
from gauth.token.store import RedisTokenStore

redis_client = redis.Redis.from_url("redis://localhost:6379")
token_store = RedisTokenStore(redis_client)
gauth = GAuth.new(config, token_store=token_store)
```

### Custom Rate Limiting

```python
from gauth.ratelimit.limiter import SlidingWindowRateLimiter
from datetime import timedelta

rate_limiter = SlidingWindowRateLimiter(
    max_requests=50,
    time_window=timedelta(minutes=1)
)
gauth = GAuth.new(config, rate_limiter=rate_limiter)
```

## Production Deployment

### Docker Production

```bash
# Build production image
docker build -t gauth-py:latest .

# Run with external services
docker-compose -f docker-compose.yml up gauth-py-full
```

### With External Services

```yaml
# docker-compose.yml snippet
services:
  gauth-py:
    image: gauth-py:latest
    environment:
      - GAUTH_REDIS_URL=redis://redis:6379/0
      - GAUTH_DATABASE_URL=postgresql://user:pass@postgres:5432/gauth
    depends_on:
      - redis
      - postgres
```

## Security Considerations

- **Secret Management**: Use environment variables or secure secret management
- **Token Expiry**: Configure appropriate token expiration times
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **Audit Logs**: Ensure audit logs are stored securely and retained appropriately
- **Network Security**: Use HTTPS for all communications
- **Input Validation**: All inputs are validated before processing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Run the test suite (`make verify`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add type hints to all functions
- Write comprehensive tests
- Update documentation for new features
- Ensure all tests pass before submitting PR

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- **GAuth Go**: Original Go implementation - https://github.com/mauriciomferz/Gauth_go
- **GAuth Protocol**: RFC 111 specification
- **PoA Standard**: RFC 115 specification

## Support

- **Documentation**: Comprehensive guides in `docs/`
- **Examples**: Runnable examples in `examples/`
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Community discussions on GitHub Discussions

---

**Note**: This is the Python implementation of GAuth. For the original Go implementation, see [Gauth_go](https://github.com/mauriciomferz/Gauth_go).

## Changelog

### Version 0.1.0 (Initial Release)
- ✅ Core GAuth protocol implementation
- ✅ Async/await support
- ✅ Comprehensive audit logging
- ✅ Rate limiting with multiple algorithms
- ✅ Redis and PostgreSQL support
- ✅ Docker and docker-compose setup
- ✅ Extensive examples and tests
- ✅ Type hints and documentation