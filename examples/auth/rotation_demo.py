"""Demonstration of JWT signing key rotation with grace validation.

Steps:
1. Create AuthService with rotation enabled and short intervals for demo.
2. Generate initial token (kid_1).
3. Force rotate -> generate second token (kid_2).
4. Validate first (should still be valid in grace) and second (active).
5. Simulate grace expiry by manipulating internal key timestamps (demo only) and attempt validation again.

NOTE: This script uses internal attributes for demonstration; production code should
expose formal APIs for forced expiry if needed for testing.
"""

import asyncio
from datetime import timedelta, datetime, timezone

from gauth.auth.types import AuthType, TokenRequest
from gauth.auth.service import create_auth_service
from gauth.token.rotation import RotationPolicy


async def main():
    service = create_auth_service(
        auth_type=AuthType.JWT,
        access_token_expiry=timedelta(minutes=10),
        extra_config={'secret_key': 'demo-root-secret'},
    )
    # Rebuild service enabling rotation (factory doesn't yet expose flag directly)
    service = service.__class__(service.config, enable_rotation=True, rotation_policy=RotationPolicy(
        rotation_interval=timedelta(seconds=2),
        grace_period=timedelta(seconds=4),
        max_active_keys=3,
    ))
    await service.initialize()

    # Issue first token
    req1 = TokenRequest(grant_type="client_credentials", subject="user1", scope="read write")
    t1 = await service.generate_token(req1)
    print("Token1:", t1.access_token[:60], '...')

    # Force rotation
    await service.rotation_manager.force_rotate()  # type: ignore
    req2 = TokenRequest(grant_type="client_credentials", subject="user1", scope="read write")
    t2 = await service.generate_token(req2)
    print("Token2:", t2.access_token[:60], '...')

    # Validate both
    td1 = await service.validate_token(t1.access_token)
    td2 = await service.validate_token(t2.access_token)
    print("Validate token1 (grace):", bool(td1))
    print("Validate token2 (active):", bool(td2))

    # Wait for grace to expire
    await asyncio.sleep(5)
    td1_after = await service.validate_token(t1.access_token)
    print("Validate token1 after grace (expected False):", bool(td1_after))

    # Show keys
    if service.rotation_manager:  # type: ignore
        keys = await service.rotation_manager.list_keys()  # type: ignore
        for k in keys:
            print(f"Key {k.key_id} status={k.status} created={k.created_at.time()} expires={k.expires_at.time()}")

    await service.authenticator.close()


if __name__ == "__main__":
    asyncio.run(main())
