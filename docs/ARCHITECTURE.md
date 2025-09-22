# GAuth Python Architecture Guide

---

## Legal Compliance & Framework

**Important**: For all legal provisions, licensing details, compliance requirements, and technical exclusions, see the authoritative source:

📋 **[LEGAL_FRAMEWORK.md](../LEGAL_FRAMEWORK.md)** - Complete legal compliance guide

This architecture document focuses on technical implementation details. All legal questions should be directed to the centralized legal framework document.

---

## Overview

GAuth Python is designed with a modular, async-first architecture that prioritizes:
- Type safety with comprehensive type hints
- Clear separation of concerns
- Extensibility through interfaces and dependency injection
- Security best practices with comprehensive audit trails
- High performance with async/await patterns

## Architecture Layers

**Note:**
- All public APIs use type hints and Pydantic models (no untyped dictionaries)
- Rate limiting is enforced per user and per client using token owner information
- All operations are async-first for maximum scalability

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                      │
│                     (Python async clients)                     │
└─────────────────────────────────────────────────────────────────┘
                                  │
                         HTTP/HTTPS (async)
                                  │
┌─────────────────────────────────────────────────────────────────┐
│                          GAuth API Layer                       │
│                      (FastAPI/async endpoints)                 │
└─────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────────────────────────────────────┐
│                      Core GAuth Protocol                       │
│               (gauth.core.gauth.GAuth class)                   │
└─────────────────────────────────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Authentication │    │  Authorization  │    │  Token & Store  │
│   (gauth.auth)  │    │  (gauth.authz)  │    │ (gauth.token*)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Audit & Events  │    │ Rate Limiting   │    │   Resilience    │
│(gauth.audit/    │    │ (gauth.rate*/   │    │ (gauth.circuit/ │
│ gauth.events)   │    │  ratelimit)     │    │  resilience)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Storage & External                        │
│              (Redis, PostgreSQL, External APIs)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## P*P Roles (Power*Point Architecture)

GAuth Python explicitly implements the Power*Point (P*P) roles as defined in RFC 0111:

### Core Components

- **🛡️ Power Enforcement Point (PEP)**: Enforces access control decisions
  - `gauth.authz.enforcement.PowerEnforcementPoint`
  - Validates tokens and scopes for each request
  - Integrates with rate limiting and audit logging

- **🧠 Power Decision Point (PDP)**: Makes authorization decisions  
  - `gauth.authz.decision.PowerDecisionPoint`
  - Evaluates policies against request context
  - Supports complex rule evaluation and scope checking

- **📊 Power Information Point (PIP)**: Gathers attributes/context for decisions
  - `gauth.core.context` and configuration systems
  - Collects user attributes, client information, and environmental context
  - Supports async context gathering for performance

- **⚙️ Power Administration Point (PAP)**: Manages policies and revocation
  - `gauth.authz.admin.PowerAdministrationPoint`
  - Handles policy updates, token revocation, and administrative operations
  - Provides async APIs for policy management

- **✅ Power Verification Point (PVP)**: Verifies tokens and identities
  - `gauth.auth.verification.PowerVerificationPoint`  
  - Validates JWT tokens, PASETO tokens, and other credentials
  - Supports multiple verification backends

---

## Package Architecture

### Core Packages

#### `gauth.core` - Protocol Implementation
- **`gauth.py`**: Main GAuth class coordinating all operations
- **`config.py`**: Configuration management with environment variable support
- **`types.py`**: Core type definitions using Pydantic models

#### `gauth.auth` - Authentication Systems
- **`jwt_auth.py`**: JWT authentication with HS256/RS256 support
- **`oauth2_auth.py`**: OAuth 2.0 authorization code and client credentials flows
- **`paseto_auth.py`**: PASETO v2 local token authentication  
- **`basic_auth.py`**: Username/password authentication
- **`service.py`**: Unified authentication service

#### `gauth.authz` - Authorization Framework
- **`enforcer.py`**: Policy enforcement engine
- **`policies.py`**: Policy definition and evaluation
- **`scopes.py`**: Scope-based access control

#### `gauth.token` - Token Management
- **`types.py`**: Token type definitions
- **`generator.py`**: Token generation with multiple algorithms
- **`validator.py`**: Token validation and verification

#### `gauth.tokenstore` - Token Storage
- **`memory.py`**: In-memory token storage for development
- **`redis.py`**: Redis-based distributed token storage
- **`interface.py`**: Storage interface abstractions

### Supporting Packages

#### `gauth.audit` - Audit Logging
- **`console.py`**: Console audit logger
- **`file.py`**: File-based audit logging
- **`poa.py`**: Specialized RFC 115 Power-of-Attorney audit logging

#### `gauth.rate` & `gauth.ratelimit` - Rate Limiting
- **Token bucket, sliding window, adaptive algorithms**
- **Per-client and per-user rate limiting**
- **Redis-backed distributed rate limiting**

#### `gauth.resilience` - Fault Tolerance
- **`circuit_breaker.py`**: Circuit breaker pattern implementation
- **`retry.py`**: Exponential backoff retry mechanisms
- **`timeout.py`**: Request timeout handling

#### `gauth.events` - Event System
- **`bus.py`**: Event bus for loose coupling
- **`handlers.py`**: Event handler registration and dispatch

---

## Design Principles

### 1. **Async-First Architecture**
- All I/O operations use async/await
- Non-blocking database and external service calls
- Concurrent request processing with proper resource management

### 2. **Type Safety**
- Comprehensive type hints throughout the codebase
- Pydantic models for data validation and serialization
- mypy static type checking in CI/CD

### 3. **Modular Design**
- Clear interface definitions for extensibility
- Dependency injection for testing and customization
- Plugin architecture for custom authentication/authorization backends

### 4. **Security by Default**
- Secure defaults for all configuration options
- Comprehensive input validation using Pydantic
- Audit logging enabled by default with secure storage

### 5. **Performance Optimization**
- Redis caching for frequently accessed data
- Connection pooling for database operations
- Efficient rate limiting algorithms with minimal overhead

---

## Data Flow

### 1. **Authorization Request Flow**
```python
Client Request → GAuth.initiate_authorization() → AuthN Validation → 
Policy Evaluation → Grant Generation → Audit Logging → Response
```

### 2. **Token Request Flow**  
```python
Grant Presentation → GAuth.request_token() → Grant Validation →
Token Generation → Token Storage → Rate Limit Check → Response
```

### 3. **Transaction Processing Flow**
```python
Transaction + Token → GAuth.process_transaction() → Token Validation →
Scope Verification → Business Logic → Audit Logging → Response
```

---

## Configuration

### Environment-Based Configuration
```python
# Core settings
GAUTH_AUTH_SERVER_URL=https://auth.example.com
GAUTH_CLIENT_ID=your-client-id
GAUTH_CLIENT_SECRET=your-client-secret

# Storage configuration
GAUTH_REDIS_URL=redis://localhost:6379
GAUTH_POSTGRES_URL=postgresql://user:pass@localhost/gauth

# Security settings
GAUTH_JWT_SECRET=your-jwt-secret
GAUTH_TOKEN_EXPIRY=3600

# Rate limiting
GAUTH_RATE_LIMIT_PER_MINUTE=100
GAUTH_RATE_LIMIT_BURST=10
```

### Programmatic Configuration
```python
from gauth import Config, GAuth

config = Config(
    auth_server_url="https://auth.example.com",
    client_id="my-client",
    client_secret="my-secret",
    redis_url="redis://localhost:6379",
    rate_limit_per_minute=100,
    audit_backend="file",
    audit_file_path="/var/log/gauth-audit.log"
)

gauth = GAuth.new(config)
```

---

## Security Considerations

### Authentication Security
- Strong JWT secret management with environment variables
- Token expiration and automatic refresh
- Multi-factor authentication support

### Authorization Security  
- Principle of least privilege with fine-grained scopes
- Policy-based access control with audit trails
- Rate limiting to prevent abuse

### Audit Security
- Tamper-evident audit logs with cryptographic hashing
- Secure storage with appropriate retention policies
- Real-time audit event streaming for monitoring

### Network Security
- HTTPS-only communication
- Certificate validation for external services
- Request/response encryption for sensitive data

---

## Extension Points

### Custom Authentication Backends
```python
from gauth.auth.interface import AuthenticationBackend

class CustomAuthBackend(AuthenticationBackend):
    async def authenticate(self, credentials: dict) -> AuthResult:
        # Custom authentication logic
        pass
```

### Custom Authorization Policies
```python
from gauth.authz.interface import PolicyEvaluator

class CustomPolicyEvaluator(PolicyEvaluator):
    async def evaluate(self, context: AuthContext) -> PolicyResult:
        # Custom policy evaluation logic  
        pass
```

### Custom Audit Backends
```python
from gauth.audit.interface import AuditBackend

class CustomAuditBackend(AuditBackend):
    async def log_event(self, event: AuditEvent) -> None:
        # Custom audit logging logic
        pass
```

---

## Testing Architecture

### Unit Testing
- Comprehensive unit tests for all core components
- Mock external dependencies for isolation
- Property-based testing for edge cases

### Integration Testing  
- End-to-end flow testing with real backends
- Docker-based testing environments
- Performance testing with load simulation

### Compliance Testing
- RFC 111 & RFC 115 compliance verification
- Security vulnerability scanning
- Legal provision compliance automated testing

---

## Deployment Considerations

### Production Deployment
- Docker containerization with multi-stage builds
- Kubernetes deployment manifests
- Health checks and readiness probes

### Monitoring & Observability
- Prometheus metrics for performance monitoring
- Structured logging with log aggregation
- Distributed tracing for request flow analysis

### Scalability
- Horizontal scaling with stateless design
- Redis clustering for distributed state
- Database connection pooling and optimization

---

**For complete legal provisions, compliance requirements, and licensing information, refer to [LEGAL_FRAMEWORK.md](../LEGAL_FRAMEWORK.md).**