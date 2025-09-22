import asyncio
import pytest

from gauth.auth.service import AuthService, AuthServiceConfig
from gauth.auth.types import TokenRequest
from gauth.policy.registry import (
    PolicyRegistry,
    ScopeRestrictionPolicy,
    JurisdictionPolicy,
    DelegationDepthPolicy,
    PolicyPhase,
)


@pytest.mark.asyncio
async def test_policy_issuance_scope_restriction_blocks():
    registry = PolicyRegistry()
    registry.register(ScopeRestrictionPolicy(forbidden_scopes=["admin", "root"]))
    cfg = AuthServiceConfig(audience="api")
    service = AuthService(cfg, policy_registry=registry)
    req = TokenRequest(grant_type="client_credentials", subject="user1", scope="read admin")
    # Should raise due to forbidden scope
    with pytest.raises(Exception) as exc:
        await service.generate_token(req)
    assert "forbidden scopes" in str(exc.value)


@pytest.mark.asyncio
async def test_policy_validation_jurisdiction_allows_and_blocks():
    registry = PolicyRegistry()
    registry.register(JurisdictionPolicy(allowed_jurisdictions=["us", "eu"]))
    cfg = AuthServiceConfig(audience="api")
    service = AuthService(cfg, policy_registry=registry)
    good_req = TokenRequest(grant_type="client_credentials", subject="user1", scope="read", audience="api")
    token_resp = await service.generate_token(good_req)
    allowed = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "us"})
    assert allowed is not None
    blocked = await service.validate_token(token_resp.access_token, expected_audiences=["api"], policy_metadata={"jurisdiction": "cn"})
    assert blocked is None


@pytest.mark.asyncio
async def test_delegation_depth_policy():
    registry = PolicyRegistry()
    registry.register(DelegationDepthPolicy(max_depth=2))
    # Increase expiry to avoid accidental expiry in fast tests
    cfg = AuthServiceConfig(audience="api")
    cfg.access_token_expiry = __import__("datetime").timedelta(minutes=5)
    service = AuthService(cfg, policy_registry=registry)
    req = TokenRequest(grant_type="client_credentials", subject="user1", scope="read")
    token_resp = await service.generate_token(req)
    ok = await service.validate_token(token_resp.access_token, policy_metadata={"delegation_depth": 2})
    assert ok is not None
    too_deep = await service.validate_token(token_resp.access_token, policy_metadata={"delegation_depth": 5})
    assert too_deep is None
