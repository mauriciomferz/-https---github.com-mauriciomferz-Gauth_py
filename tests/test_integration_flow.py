import asyncio
import os
import pytest

from gauth.auth.service import AuthService, AuthServiceConfig
from gauth.auth.types import TokenRequest
from gauth.policy.registry import (
    PolicyRegistry,
    ScopeRestrictionPolicy,
    JurisdictionPolicy,
    DelegationDepthPolicy,
)
from gauth.ratelimit.redis_limiter import RedisRateLimiter, RedisRateLimiterConfig  # type: ignore
from redis.exceptions import ConnectionError as RedisConnectionError  # type: ignore
try:
    from gauth.monitoring import (
        get_metric,
        METRIC_TOKENS_ISSUED,
        METRIC_TOKEN_VALIDATIONS,
        METRIC_ACTIVE_TOKENS,
    )
except Exception:  # pragma: no cover - metrics optional
    get_metric = None  # type: ignore
    METRIC_TOKENS_ISSUED = "tokens_issued_total"  # type: ignore
    METRIC_TOKEN_VALIDATIONS = "token_validations_total"  # type: ignore
    METRIC_ACTIVE_TOKENS = "active_tokens"  # type: ignore

# NOTE: Delegation chain utilities would normally come from a dedicated module; for now
# we simulate delegation depth metadata passing to policy registry.


@pytest.mark.asyncio
async def test_end_to_end_issuance_delegation_policy_revoke(redis_available=False):
    """End-to-end scenario:
    1. Issue token (valid scopes)
    2. Validate (jurisdiction allowed)
    3. Simulate delegation within depth limit
    4. Simulate excessive delegation depth -> fail
    5. Revoke token -> subsequent validation fails
    """

    registry = PolicyRegistry()
    registry.register(ScopeRestrictionPolicy(forbidden_scopes=["admin"]))
    registry.register(JurisdictionPolicy(allowed_jurisdictions=["us", "eu"]))
    registry.register(DelegationDepthPolicy(max_depth=3))

    service = AuthService(AuthServiceConfig(audience="api"), policy_registry=registry)

    # 1. Issue
    req = TokenRequest(grant_type="client_credentials", subject="alice", scope="read write", audience="api")
    token_resp = await service.generate_token(req)
    assert token_resp.access_token

    # 2. Validate (allowed jurisdiction)
    td = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "us", "delegation_depth": 1})
    assert td is not None

    # 3. Delegation depth within limit (simulate)
    td_ok = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "us", "delegation_depth": 3})
    assert td_ok is not None

    # 4. Delegation depth exceeded
    td_fail = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "us", "delegation_depth": 5})
    assert td_fail is None

    # 5. Revoke
    revoked = await service.revoke_token(token_resp.access_token)
    assert revoked is True
    td_after_revoke = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "us", "delegation_depth": 2})
    assert td_after_revoke is None

    # (Optional) Rate limiting hook placeholder: real integration pending redis-enabled rate limiter wiring.
    # This keeps test fast & infrastructure optional while documenting intended extension.


@pytest.mark.asyncio
async def test_end_to_end_with_rate_limit():
    """Extended end-to-end scenario including Redis rate limiting (if available).
    Flow:
      1. Issue token
      2. Perform validations gated by Redis token bucket (capacity=2)
      3. Third attempt should be rate limited (blocked before validation)
      4. Metrics reflect allowed/denied counts
    Skips gracefully if redis library or server not available.
    """

    try:
        import redis.asyncio  # type: ignore  # noqa: F401
    except Exception:
        pytest.skip("redis library not installed")

    registry = PolicyRegistry()
    registry.register(ScopeRestrictionPolicy(forbidden_scopes=["admin"]))
    registry.register(JurisdictionPolicy(allowed_jurisdictions=["us"]))
    registry.register(DelegationDepthPolicy(max_depth=3))

    service = AuthService(AuthServiceConfig(audience="api"), policy_registry=registry)
    req = TokenRequest(grant_type="client_credentials", subject="bob", scope="read", audience="api")
    token_resp = await service.generate_token(req)
    assert token_resp.access_token

    rl = RedisRateLimiter(
        name="integration_rl",
        config=RedisRateLimiterConfig(capacity=2, refill_tokens=2, interval_seconds=60),
        url=os.getenv("REDIS_TEST_URL", "redis://localhost:6379/0"),
    )

    allowed_validations = 0
    try:
        for attempt in range(3):
            allowed, meta = await rl.allow("bob")
            if attempt < 2:
                # First two should be allowed
                assert allowed, f"Attempt {attempt} unexpectedly rate limited: {meta}"
                td = await service.validate_token(
                    token_resp.access_token,
                    expected_audiences=["api"],
                    policy_metadata={"jurisdiction": "us", "delegation_depth": 1},
                )
                assert td is not None
                allowed_validations += 1
            else:
                # Third should be denied
                assert not allowed, "Third attempt should be rate limited"
                # We simulate enforcement by NOT calling validate_token
        metrics = rl.get_metrics()
        assert metrics["allowed"] >= 2
        assert metrics["denied"] >= 1
    except RedisConnectionError:
        pytest.skip("Redis server not reachable")
    finally:
        await rl.close()

    assert allowed_validations == 2


@pytest.mark.asyncio
async def test_delegation_chain_real_issue():
    """Integration test creating a real delegated token with custom claims.

    Steps:
      1. Issue root token (scope: read write delete)
      2. Issue delegated token referencing parent (parent_jti) with narrowed scope (read write)
      3. Issue second-level delegated token with further narrowed scope (read) depth=3
      4. Validate second-level token with metadata delegation_depth=3 succeeds
      5. Attempt validation with depth=6 (exceeds) fails due to DelegationDepthPolicy
    """

    registry = PolicyRegistry()
    registry.register(ScopeRestrictionPolicy(forbidden_scopes=["admin"]))
    registry.register(JurisdictionPolicy(allowed_jurisdictions=["us"]))
    registry.register(DelegationDepthPolicy(max_depth=5))

    service = AuthService(AuthServiceConfig(audience="api"), policy_registry=registry)

    # 1. Root token
    root_req = TokenRequest(
        grant_type="client_credentials",
        subject="carol",
        scope="read write delete",
        audience="api",
        custom_claims={"delegation_depth": 1},
    )
    root_resp = await service.generate_token(root_req)
    assert root_resp.access_token

    # Extract root jti (for mock tokens we parse JSON section; for real JWT we skip linking if not decodable)
    import json
    parent_jti = None
    token_parts = root_resp.access_token.split('.')
    if len(token_parts) >= 3 and token_parts[0] == 'mock' and token_parts[1] == 'jwt':
        try:
            claims_json = '.'.join(token_parts[2:])
            claims = json.loads(claims_json)
            parent_jti = claims.get('jti')
        except Exception:
            parent_jti = None

    # 2. First delegated token
    delegated_req_lvl1 = TokenRequest(
        grant_type="client_credentials",
        subject="carol",
        scope="read write",
        audience="api",
        custom_claims={
            "delegation_depth": 2,
            "parent_jti": parent_jti,
        },
    )
    lvl1_resp = await service.generate_token(delegated_req_lvl1)
    assert lvl1_resp.access_token

    # 3. Second-level delegated token further narrows scope
    delegated_req_lvl2 = TokenRequest(
        grant_type="client_credentials",
        subject="carol",
        scope="read",
        audience="api",
        custom_claims={
            "delegation_depth": 3,
            "parent_jti": parent_jti,  # Could also chain to lvl1 jti if extractable; simplified here
        },
    )
    lvl2_resp = await service.generate_token(delegated_req_lvl2)
    assert lvl2_resp.access_token

    # 4. Validate second-level token within depth
    td_ok = await service.validate_token(
        lvl2_resp.access_token,
        expected_audiences=["api"],
        policy_metadata={"delegation_depth": 3, "jurisdiction": "us"},
    )
    assert td_ok is not None

    # 5. Exceed depth during validation
    td_fail = await service.validate_token(
        lvl2_resp.access_token,
        expected_audiences=["api"],
        policy_metadata={"delegation_depth": 6, "jurisdiction": "us"},
    )
    assert td_fail is None


@pytest.mark.asyncio
async def test_metrics_basic_flow():
    """Verify metrics counters increment for issuance, validation, and active token gauge.
    Skips if metrics subsystem not importable.
    """
    if get_metric is None:
        pytest.skip("metrics subsystem not available")

    registry = PolicyRegistry()
    service = AuthService(AuthServiceConfig(audience="api"), policy_registry=registry)

    # Issue token
    req = TokenRequest(grant_type="client_credentials", subject="dave", scope="read", audience="api")
    resp = await service.generate_token(req)
    assert resp.access_token

    issued_metric = get_metric(METRIC_TOKENS_ISSUED)
    assert issued_metric is not None and issued_metric.value >= 1

    # Validate token
    td = await service.validate_token(resp.access_token, expected_audiences=["api"], policy_metadata={})
    assert td is not None
    validations_metric = get_metric(METRIC_TOKEN_VALIDATIONS)
    assert validations_metric is not None and validations_metric.value >= 1

    active_metric = get_metric(METRIC_ACTIVE_TOKENS)
    assert active_metric is not None and active_metric.value >= 1

    # Revoke and ensure active gauge updates
    await service.revoke_token(resp.access_token)
    active_after = get_metric(METRIC_ACTIVE_TOKENS)
    assert active_after is not None and active_after.value == 0
