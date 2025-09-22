# Token Rotation & Verification Expansion Design

## Goals
Provide a secure signing key rotation lifecycle mirroring Go `rotation.go`, enabling:
1. Periodic generation of new signing keys (primary / active)
2. Grace period where previous key(s) still validate existing tokens
3. Automatic retirement of expired keys beyond grace window
4. Integration with token validation path (AuthService + jwt/paseto managers)
5. Optional persistence (in-memory first; future: Redis)

## Concepts
- RotationManager: orchestrates key schedule & registry
- KeyRecord: dataclass with key_id, created_at, not_before, expires_at, status (ACTIVE, GRACE, RETIRED)
- KeyStore Interface: in-memory map now; pluggable later
- RotationPolicy: config (rotation_interval, grace_period, max_active_keys)

## Data Structures
```python
@dataclass
class RotationPolicy:
    rotation_interval: timedelta = timedelta(hours=12)
    grace_period: timedelta = timedelta(hours=24)
    max_active_keys: int = 3  # safety bound

@dataclass
class KeyRecord:
    key_id: str
    secret: bytes
    created_at: datetime
    status: KeyStatus  # ACTIVE | GRACE | RETIRED
    not_before: datetime
    expires_at: datetime  # created_at + rotation_interval + grace_period
```

## Lifecycle
1. Startup: if no keys, generate initial ACTIVE key.
2. On schedule (rotation_interval elapsed since last ACTIVE creation):
   - Demote current ACTIVE -> GRACE (set status, keep until expires_at)
   - Generate new ACTIVE
   - Purge any GRACE keys whose expires_at < now
3. Validation: Accept tokens signed by any key whose status in {ACTIVE, GRACE}. Reject RETIRED.

## Token Changes
- JWT Manager: embed `kid` in header when signing; during validation lookup by kid.
- Paseto Manager: include custom claim `kid` (mock scenario) for compatibility.

## Interfaces
```python
class RotationManager:
    def get_active_key(self) -> KeyRecord: ...
    def get_key(self, key_id: str) -> Optional[KeyRecord]: ...
    async def rotate_if_needed(self) -> None: ...
    async def force_rotate(self) -> KeyRecord: ...
    async def list_keys(self) -> List[KeyRecord]: ...
```

## Verification Expansion
Add helper `verify_standard_claims(token_data, expected_aud=None, required_scopes=None, not_before_skew=5s)` to centralize:
- Expiry check
- Not-before with allowed clock skew
- Audience membership (any-of vs all-of mode)
- Scope superset check
- Revocation registry query (future)

## Edge Cases & Mitigations
| Edge Case | Mitigation |
|-----------|------------|
| Concurrent rotation triggers | `asyncio.Lock` around rotate sequence |
| Clock skew causing premature expiry | configurable skew intervals |
| Excess key accumulation | enforce `max_active_keys` culling strategy |
| Missing kid in legacy token | fallback to current ACTIVE key if within issuance time window |

## Phased Implementation
Phase 1: In-memory RotationManager + JWT kid injection & validation path integration.
Phase 2: Paseto kid claim + verification hook.
Phase 3: Redis persistence + distributed coordination (advisory lock key).
Phase 4: Expose metrics (#keys, rotations, validation by status).

## Testing Scenarios
1. Issue token, rotate, validate pre & post rotation (should pass).
2. After grace expiry, old token fails.
3. Rapid forced rotations maintain cap of max_active_keys.
4. Missing kid token accepted if issued_before < first rotation time.
5. Validation rejects token signed with RETIRED key.

---
Draft ready for implementation.