import asyncio
from datetime import timedelta

import pytest

from gauth.auth.types import AuthType, TokenRequest
from gauth.auth.service import create_auth_service, AuthServiceConfig
from gauth.token.rotation import RotationPolicy

pytestmark = pytest.mark.asyncio


async def issue(service, subject="user", scope="read"):
    req = TokenRequest(grant_type="client_credentials", subject=subject, scope=scope)
    return await service.generate_token(req)


@pytest.fixture
async def rotation_service():
    config = AuthServiceConfig(auth_type=AuthType.JWT, access_token_expiry=timedelta(minutes=5), extra_config={"secret_key": "test-secret"})
    service = create_auth_service(auth_type=AuthType.JWT, access_token_expiry=timedelta(minutes=5), extra_config={"secret_key": "test-secret"})
    # Replace with rotation-enabled instance
    service = service.__class__(config, enable_rotation=True, rotation_policy=RotationPolicy(
        rotation_interval=timedelta(seconds=1),
        grace_period=timedelta(seconds=2),
        max_active_keys=5,
    ))
    await service.initialize()
    yield service
    await service.authenticator.close()


async def test_rotation_grace_validation(rotation_service):
    t1 = await issue(rotation_service)
    # Force rotation
    await rotation_service.rotation_manager.force_rotate()  # type: ignore
    t2 = await issue(rotation_service)

    # Old token should still validate (grace)
    td1 = await rotation_service.validate_token(t1.access_token)
    td2 = await rotation_service.validate_token(t2.access_token)
    assert td1 is not None, "Old token should validate during grace period"
    assert td2 is not None, "New token should validate"

    # Expire grace keys and ensure old token fails
    await rotation_service.rotation_manager.expire_grace_keys()  # type: ignore
    td1_post = await rotation_service.validate_token(t1.access_token)
    assert td1_post is None, "Old token should fail after grace expiration"


async def test_multiple_forced_rotations(rotation_service):
    tokens = []
    for _ in range(3):
        tokens.append((await issue(rotation_service)).access_token)
        await rotation_service.rotation_manager.force_rotate()  # type: ignore

    # All tokens except the last may be in grace / active; after expiring grace only last should validate
    await rotation_service.rotation_manager.expire_grace_keys()  # type: ignore
    valid_count = 0
    for tok in tokens:
        if await rotation_service.validate_token(tok):
            valid_count += 1
    assert valid_count <= 1, "At most one token (latest) should remain valid after expiring grace keys"


async def test_max_active_keys_trim(rotation_service):
    # Force more rotations than max_active_keys
    for _ in range(10):
        await rotation_service.rotation_manager.force_rotate()  # type: ignore
        await asyncio.sleep(0.01)
    rm = rotation_service.rotation_manager  # type: ignore
    # Internal invariant: non-retired keys should not exceed policy.max_active_keys
    keys = await rm.list_keys()  # type: ignore
    non_retired = [k for k in keys if k.status.value != 'retired']
    assert len(non_retired) <= rm.policy.max_active_keys  # type: ignore
