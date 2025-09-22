# Go -> Python Package Mapping

This document maps the original `Gauth_go` Go packages under `pkg/` to their Python counterparts in `Gauth_py/gauth/` and notes parity status.

| Go Package | Key Files / Concepts | Python Module | Parity | Notes |
|------------|----------------------|---------------|--------|-------|
| auth | `auth.go`, managers (`jwt.go`, `oauth2.go`, `paseto.go`, `basic.go`), `service.go`, errors | `gauth/auth/` (`auth.py`, `jwt.py`, `oauth2.py`, `paseto.py`, `basic.py`, `service.py`, `errors.py`) | High | Core flows implemented; legal framework stubs partially omitted; refresh logic adapted. |
| token | `manager.go`, `service.go`, `jwt.go`, `rotation.go`, stores | `gauth/token/` | High | Rotation simplified; store abstraction present; advanced delegation partially merged into auth layer. |
| ratelimit | `token_bucket.go`, `sliding_window.go`, `adaptive_ratelimiter.go` | `gauth/ratelimit/` | High | Token bucket, sliding, fixed & adaptive (client) implemented. |
| rate | Higher-level rate orchestration, middleware | Integrated across `ratelimit` & examples | Medium | Some orchestration patterns folded into examples. |
| resilience | `circuit.go`, `patterns.go` (retry/timeout) | `gauth/resilience/` | Medium | Circuit + retry implemented; timeouts simplified. |
| events | Bus, dispatcher, metadata, typed metadata | `gauth/events/` | High | Event bus & typed metadata supported. |
| authz | Policy evaluation, conditions | `gauth/authz/` | Medium | Core request/context & evaluation patterns; some edge tests not ported. |
| poa | RFC 115 principals, authorization | `gauth/poa/` | High | Principal, Client, Authorization, Requirements present. |
| monitoring | Metrics collection | `gauth/monitoring/` | Medium | Basic metrics & health tracking; exporters minimal. |
| audit | Audit logging | `gauth/audit/` | Medium | Core audit trail primitives present. |
| store | Memory/Redis factories | `gauth/store/` | Medium | Memory store stable; Redis placeholders. |
| tokenstore | Specialized token store impls | `gauth/tokenstore/` | Medium | Memory token store; redis stub. |
| mesh | Service mesh integration stubs | `gauth/mesh/` | Low | High-level interfaces only. |
| resources / resource | Resource descriptors & metadata | `gauth/resources/` | Medium | Typed resource models included. |
| common/util | Helpers (`time_range.go`) | `gauth/common/`, `gauth/util/` | High | Time helpers (`get_current_time`) added. |
| errors | Rich error taxonomy | `gauth/errors/` | High | Structured error classes & enums. |
| types | Shared type models | Distributed across modules (`types.py`) | High | Consolidated with auth/token types.

## Outstanding Minor Gaps

- Basic auth token format remains simplistic (base64 of dict string) – acceptable for demo level.
- PASETO uses mock tokens unless `pyseto` installed.
- Some advanced legal framework / compliance stubs from Go not yet ported (low runtime impact).
- Rate middleware and distributed coordination patterns condensed into simpler API surfaces.

## Recently Applied Polish

- Fixed BasicAuth initialization ordering (avoids attribute error before config set).
- Normalized PASETO to timezone-aware UTC datetimes preventing naive/aware comparison warnings.

## Next Possible Enhancements

1. Implement full token rotation lifecycle mirroring Go `rotation.go`.
2. Add Redis-backed rate limiter & token store implementations.
3. Port advanced legal framework enforcement examples.
4. Expand resilience timeouts and bulkhead patterns.
5. Harden basic auth token to signed/encoded structure (e.g., JWT or HMAC). 

---
Generated as part of conversion parity tracking.