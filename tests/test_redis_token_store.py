import os
import pytest
from datetime import timedelta

from gauth.tokenstore.redis import RedisTokenStore
from gauth.tokenstore.store import TokenData
from redis.exceptions import ConnectionError as RedisConnectionError  # type: ignore

pytestmark = pytest.mark.asyncio

REDIS_URL = os.getenv("REDIS_TEST_URL", "redis://localhost:6379/0")


@pytest.mark.asyncio
async def test_redis_token_store_crud():
    try:
        import redis.asyncio  # type: ignore
    except Exception:
        pytest.skip("redis library not installed")

    store = RedisTokenStore(url=REDIS_URL, ttl=30, enable_indexes=True, enable_all_index=True)
    token = "tok-1"
    data = TokenData(client_id="c1", owner_id="u1", scope=["read"], subject="u1")
    try:
        await store.store(token, data)
        fetched = await store.get(token)
        assert fetched and fetched.client_id == "c1"
        assert await store.exists(token)
        listed_client = await store.get_tokens_by_client("c1")
        assert listed_client and listed_client[0].client_id == "c1"
        count = await store.count_tokens()
        assert count >= 1
        stats = await store.get_statistics()
        assert stats["total_tokens"] >= 1
        # revoke
        await store.revoke(token)
        revoked = await store.get(token)
        assert revoked and revoked.status.value == "revoked"
        await store.delete(token)
        assert not await store.exists(token)
    except RedisConnectionError:
        pytest.skip("Redis server not reachable")
