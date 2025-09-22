import importlib
import pytest


def redis_available():
    try:
        importlib.import_module("redis.asyncio")
        return True
    except Exception:
        return False


@pytest.mark.asyncio
async def test_import_redis_token_store():
    if not redis_available():
        pytest.skip("redis library not installed")
    mod = importlib.import_module("gauth.tokenstore")
    assert hasattr(mod, "RedisTokenStore")


@pytest.mark.asyncio
async def test_import_redis_rate_limiter():
    if not redis_available():
        pytest.skip("redis library not installed")
    rl_mod = importlib.import_module("gauth.ratelimit.redis_limiter")
    assert hasattr(rl_mod, "RedisRateLimiter")
