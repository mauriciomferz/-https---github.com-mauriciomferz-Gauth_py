import os
import pytest
import math

from gauth.ratelimit.redis_limiter import RedisRateLimiter, RedisRateLimiterConfig

from redis.exceptions import ConnectionError as RedisConnectionError  # type: ignore

pytestmark = pytest.mark.asyncio

REDIS_URL = os.getenv("REDIS_TEST_URL", "redis://localhost:6379/0")


@pytest.mark.asyncio
async def test_token_bucket_basic():
    try:
        import redis.asyncio  # type: ignore
    except Exception:
        pytest.skip("redis library not installed")

    rl = RedisRateLimiter(
        name="test",
        config=RedisRateLimiterConfig(capacity=5, refill_tokens=5, interval_seconds=60),
        url=REDIS_URL,
    )
    allowed_count = 0
    try:
        for i in range(5):
            allowed, meta = await rl.allow("user1")
            assert meta["remaining"] <= 5
            if allowed:
                allowed_count += 1
    except RedisConnectionError:
        pytest.skip("Redis server not reachable")
    assert allowed_count == 5

    # Next should be denied until refill adds tokens
    allowed, meta = await rl.allow("user1")
    assert not allowed
    assert meta["remaining"] <= 5
    assert meta["wait_ms"] >= 0

    await rl.close()


@pytest.mark.asyncio
async def test_token_bucket_cost_and_metrics():
    try:
        import redis.asyncio  # type: ignore
    except Exception:
        pytest.skip("redis library not installed")

    rl = RedisRateLimiter(
        name="metrics",
        config=RedisRateLimiterConfig(capacity=10, refill_tokens=10, interval_seconds=60),
        url=REDIS_URL,
    )

    # Consume with cost 2 until empty
    consumed = 0
    try:
        while True:
            allowed, meta = await rl.allow("acct", cost=2)
            if not allowed:
                break
            consumed += 2
            if consumed > 20:  # safety
                break
    except RedisConnectionError:
        pytest.skip("Redis server not reachable")
    metrics = rl.get_metrics()
    assert metrics["total"] >= metrics["allowed"]
    assert metrics["allowed"] >= 1
    assert metrics["denied"] >= 1

    await rl.close()
