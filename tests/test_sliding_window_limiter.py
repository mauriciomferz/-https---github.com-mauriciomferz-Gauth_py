import os
import pytest
from gauth.ratelimit.redis_limiter import RedisRateLimiter, RedisRateLimiterConfig
from redis.exceptions import ConnectionError as RedisConnectionError  # type: ignore

pytestmark = pytest.mark.asyncio

REDIS_URL = os.getenv("REDIS_TEST_URL", "redis://localhost:6379/0")


@pytest.mark.asyncio
async def test_sliding_window_basic():
    try:
        import redis.asyncio  # type: ignore
    except Exception:
        pytest.skip("redis library not installed")

    rl = RedisRateLimiter(
        name="sw",
        config=RedisRateLimiterConfig(capacity=5, refill_tokens=5, interval_seconds=10, algorithm="sliding_window"),
        url=REDIS_URL,
    )

    allowed = 0
    try:
        for _ in range(5):
            ok, meta = await rl.allow("user")
            if ok:
                allowed += 1
        assert allowed == 5
        # Next should typically be denied within same window
        ok, meta = await rl.allow("user")
        assert not ok or meta.get("fallback")
    except RedisConnectionError:
        pytest.skip("Redis server not reachable")
