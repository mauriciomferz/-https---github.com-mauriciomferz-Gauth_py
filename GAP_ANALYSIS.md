# Gap Analysis: Go (Gauth_go) vs Python (Gauth_py)

This document enumerates remaining feature or fidelity gaps between the original Go implementation and the current Python port.

## Legend
Priority: (H) High - core security/runtime behavior; (M) Medium - valuable capability; (L) Low - nice to have/stubs.

| Area | Gap Description | Go Reference (examples) | Python Status | Priority | Proposed Action |
|------|------------------|--------------------------|---------------|----------|-----------------|
| Token Rotation | Full signing key rotation lifecycle w/ grace overlap | `pkg/token/rotation.go` | Scaffolded (manager + grace validation) | H | Add scheduling + persistence integration |
| Token Verification | Enhanced verification (audience, not-before, revocation lists) | `pkg/token/validation.go` | Extended (aud, scopes, nbf, claims) | H | Add revocation registry + attestation awareness |
| Delegation / Attestation | Advanced delegated token edge cases & attestation proofs | `pkg/token/advanced_delegation_attestation_test.go` | Simplified factories | M | Implement attestation verifier + delegated chain depth checks |
| Legal Framework | Legal framework models & enforcement (compliance gating) | `pkg/auth/legal_framework*.go` | Not ported | M | Introduce lightweight compliance policy registry |
| Power Enforcement | Extended access power control | `pkg/auth/power_enforcement.go` | Absent | M | Add policy hook injecting restriction claims |
| Subscription / Extended Controls | Subscription tier constraints | `pkg/auth/subscription.go` | Absent | L | Add optional subscription claim evaluator |
| Authz Conditions | Rich conditional operators & annotation parsing | `pkg/authz/conditions.go` `annotations.go` | Core context only | M | Port condition operators + annotation parser |
| Rate Middleware | HTTP middleware integration & layered limiter composition | `pkg/rate/middleware.go` | Not present | M | Provide functional wrappers for frameworks (FastAPI example) |
| Distributed Rate Coordination | Redis-backed distributed counters | `pkg/rate/redis.go` | Partial (token bucket implemented) | H (scalability) | Add sliding window + adaptive algorithms |
| Bulkhead / Fallback Patterns | Additional resilience patterns | `pkg/resilience/patterns.go` | Circuit+retry only | M | Add bulkhead (semaphore) + fallback wrapper |
| Metrics Exporters | Prometheus style detailed metrics | `pkg/monitoring/metrics.go` | Basic counters | M | Integrate prometheus_client optional exporter |
| Event Handler Examples | Comprehensive typed metadata tests | `pkg/events/*_test.go` | Partial | L | Add typed metadata example + test |
| Redis Token Store | Production Redis implementation | `pkg/token/redis_store.go` | Scaffold (async skeleton) | H | Implement full CRUD, scanning, secondary indexes |
| Redis Generic Store | Generic resource store | `pkg/store/redis.go` | Placeholder | M | Add generic key/value TTL store |
| Time Range Utility | Time range comparison helpers | `pkg/util/time_range.go` | Missing | L | Port as `util/time_range.py` |
| Advanced Error Mapping | Granular error codes parity | `pkg/errors/*` | Mostly present | L | Audit & align enums | 
| Examples Coverage | Edge case & RFC flow examples | Multiple test files | Partial (rotation demo added) | M | Add delegation + redis examples |
| Test Coverage | Extensive Go tests | Multiple `*_test.go` | Minimal (rotation tests added) | H | Port representative critical path tests |

## High Priority Implementation Plan (Next Pass)
1. Token rotation manager (rolling keys + validation overlap)
2. Redis token store + distributed rate limiter
3. Expanded token verification (aud, nbf, revocation registry)
4. Attestation / delegated chain validation enhancements
5. AuthZ condition operators + annotation parsing port

## Supporting Enhancements
- Bulkhead + fallback resilience utilities
- Prometheus metrics optional integration
- Legal framework lightweight policy registry

## Testing Strategy
- Rotation: issue token pre-rotation, ensure valid post-rotation during overlap, invalid after grace window
- Redis rate limiter: concurrent increments across processes simulation
- Delegation: depth limit enforcement and claim inheritance integrity
- AuthZ: condition evaluation matrix (string match, numeric compare, logical composition)
- Metrics: exporter scrape endpoint returns expected counters/gauges

## Notes
Gaps prioritized to maximize security correctness (rotation, verification, distributed limits) before auxiliary policy and observability layers.

---
Generated automatically to support ongoing parity work.