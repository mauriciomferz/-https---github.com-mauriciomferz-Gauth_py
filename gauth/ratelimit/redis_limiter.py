"""Redis-backed token bucket rate limiter.

Implements an atomic token bucket using a Lua script. The bucket maintains:
 - capacity (max tokens)
 - tokens (current tokens)
 - last_refill (unix ms timestamp)

Algorithm (per allow call):
 1. Compute elapsed time since last_refill; calculate tokens_to_add = elapsed * refill_rate.
 2. Increase tokens = min(capacity, tokens + tokens_to_add).
 3. If tokens >= cost: tokens -= cost, allowed = 1 else allowed = 0.
 4. Store updated tokens and timestamp.
 5. Return allowed flag, remaining tokens, wait_time_ms until next token if denied, and reset_in (interval window end approximation).

The script sets a TTL so idle keys eventually expire.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, Any
import time

try:  # optional metrics exporter
    from ..monitoring.metrics_exporter import get_registry  # type: ignore
except Exception:  # pragma: no cover
    get_registry = None  # type: ignore


try:
    import redis.asyncio as redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class RedisRateLimiterConfig:
    # Capacity (max burst tokens)
    capacity: int = 100
    # Refill tokens per interval_seconds
    refill_tokens: int = 100
    interval_seconds: int = 60
    prefix: str = "gauth:rl"
    algorithm: str = "token_bucket"
    ttl_seconds: int = 3600  # Expire idle buckets after 1h
    # Derived: refill rate tokens per second
    @property
    def refill_rate(self) -> float:
        return self.refill_tokens / float(self.interval_seconds)

@dataclass
class RateLimiterMetrics:
    allowed: int = 0
    denied: int = 0
    errors: int = 0
    total: int = 0

    def snapshot(self) -> Dict[str, int]:
        return {
            "allowed": self.allowed,
            "denied": self.denied,
            "errors": self.errors,
            "total": self.total,
        }


class RedisRateLimiter:
    """Redis-backed token bucket rate limiter (atomic)."""

    _LUA_TOKEN_BUCKET = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])  -- tokens per ms
    local now = tonumber(ARGV[3])          -- current time ms
    local cost = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    local data = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(data[1])
    local last_refill = tonumber(data[2])

    if tokens == nil then
        tokens = capacity
        last_refill = now
    end

    -- Refill
    if now > last_refill then
        local delta = now - last_refill
        local add = delta * refill_rate
        if add > 0 then
            tokens = math.min(capacity, tokens + add)
            last_refill = now
        end
    end

    local allowed = 0
    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    end

    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
    redis.call('PEXPIRE', key, ttl * 1000)

    local wait_time_ms = 0
    if allowed == 0 then
        if refill_rate > 0 then
            wait_time_ms = math.ceil((cost - tokens) / refill_rate)
        else
            wait_time_ms = -1
        end
    end

    return {allowed, tokens, wait_time_ms}
    """

    def __init__(self, name: str, config: Optional[RedisRateLimiterConfig] = None, url: str = "redis://localhost:6379/0"):
        self.name = name
        self.config = config or RedisRateLimiterConfig()
        self.url = url
        self._client = None
        self._script_sha: Optional[str] = None
        self.metrics = RateLimiterMetrics()

    async def _get_client(self):  # pragma: no cover
        if self._client is None:
            if redis is None:
                raise RuntimeError("redis.asyncio not installed; pip install redis>=4.5")
            self._client = redis.from_url(self.url, decode_responses=True)
        return self._client

    async def _load_script(self):  # pragma: no cover
        client = await self._get_client()
        if not self._script_sha:
            self._script_sha = await client.script_load(self._LUA_TOKEN_BUCKET)
        return self._script_sha

    async def allow(self, key: str = "global", cost: int = 1) -> Tuple[bool, Dict[str, Any]]:
        self.metrics.total += 1
        client = await self._get_client()
        if self.config.algorithm == "sliding_window":
            return await self._allow_sliding_window(client, key, cost)
        sha = await self._load_script()
        bucket_key = f"{self.config.prefix}:{self.name}:{key}"
        now_ms = int(time.time() * 1000)
        refill_rate_per_ms = self.config.refill_rate / 1000.0
        try:
            allowed, tokens, wait_ms = await client.evalsha(
                sha,
                1,
                bucket_key,
                self.config.capacity,
                refill_rate_per_ms,
                now_ms,
                cost,
                self.config.ttl_seconds,
            )
            allowed = int(allowed) == 1
            if allowed:
                self.metrics.allowed += 1
            else:
                self.metrics.denied += 1
            meta = {
                "remaining": tokens,
                "wait_ms": wait_ms,
                "algorithm": self.config.algorithm,
                "capacity": self.config.capacity,
                "refill_rate_per_s": self.config.refill_rate,
                "key": key,
            }
            return allowed, meta
        except Exception as e:  # pragma: no cover
            self.metrics.errors += 1
            logger.warning(f"Redis rate limiter fallback allow due to error: {e}")
            # Fail-open strategy: allow request if Redis unavailable
            return True, {"fallback": True, "error": str(e), "key": key}

    async def _allow_sliding_window(self, client, key: str, cost: int) -> Tuple[bool, Dict[str, Any]]:
        """Fixed-size sliding window approximation using simple counters.

        Approach: maintain a key per window segment (prefix:name:key:window_start_second).
        Current window = floor(now / interval) * interval.
        Count = sum(current + previous window weighted by partial overlap fraction).
        If count + cost <= capacity -> allow; else deny. Uses two GET ops + one INCR.
        Simplified to reduce redis calls: enforce using current window only (strict window) if previous fetch fails.
        """
        interval = self.config.interval_seconds
        capacity = self.config.capacity
        now = int(time.time())
        window_start = now - (now % interval)
        current_key = f"{self.config.prefix}:{self.name}:{key}:sw:{window_start}"
        prev_key = f"{self.config.prefix}:{self.name}:{key}:sw:{window_start - interval}"
        try:
            pipe = client.pipeline()
            pipe.get(current_key)
            pipe.get(prev_key)
            current_val, prev_val = await pipe.execute()
            current = int(current_val) if current_val else 0
            prev = int(prev_val) if prev_val else 0
            elapsed = now - window_start
            overlap_ratio = max(0.0, 1.0 - (elapsed / interval))  # fraction of previous window still relevant
            effective = prev * overlap_ratio + current
            allowed = False
            if effective + cost <= capacity:
                # increment current window
                new_val = await client.incrby(current_key, cost)
                if new_val == cost:  # first set TTL
                    await client.expire(current_key, interval * 2)
                allowed = True
                self.metrics.allowed += 1
            else:
                self.metrics.denied += 1
            remaining = max(0, capacity - int(effective))
            reset_in = interval - elapsed
            meta = {
                "remaining": remaining,
                "algorithm": "sliding_window",
                "capacity": capacity,
                "interval": interval,
                "key": key,
                "reset_in": reset_in,
            }
            return allowed, meta
        except Exception as e:  # pragma: no cover
            self.metrics.errors += 1
            logger.warning(f"Sliding window fallback (allow) due to error: {e}")
            return True, {"fallback": True, "error": str(e), "key": key, "algorithm": "sliding_window"}

    async def close(self):  # pragma: no cover
        if self._client:
            try:
                await self._client.close()
            except Exception:
                pass

    def get_metrics(self) -> Dict[str, int]:
        snap = self.metrics.snapshot()
        if get_registry:
            try:  # pragma: no cover
                get_registry().observe_rate(snap, self.config.algorithm)
            except Exception:
                pass
        return snap

__all__ = ["RedisRateLimiter", "RedisRateLimiterConfig", "RateLimiterMetrics"]