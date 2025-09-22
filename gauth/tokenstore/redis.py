"""Redis-backed token store implementation (enhanced from scaffold).

Features added:
- Basic CRUD with TTL
- Optional secondary indexes (client_id / owner_id) via Redis Sets
- Listing and scanning tokens (bounded SCAN)
- Revocation (status mutation) and valid count estimation
- Statistics summary

Design Notes:
- Secondary indexes are opt-in (enabled when enable_indexes=True). Each token is stored as a JSON blob at key: f"{prefix}:data:{token}".
- Index membership keys: `{prefix}:client:{client_id}` and `{prefix}:owner:{owner_id}` store token ids.
- A global set `{prefix}:all` tracks all tokens (can be large; optional, guarded by enable_all_index flag).
- SCAN used for global listing with a safety cap to prevent unbounded iteration.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta, datetime
from typing import Optional, List, Dict, Any, Tuple, Iterable

try:  # Optional dependency
    import redis.asyncio as redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

from .store import TokenStore, TokenData, TokenStatus

logger = logging.getLogger(__name__)


class RedisTokenStore(TokenStore):
    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        prefix: str = "gauth:token",
        ttl: Optional[int] = None,
        enable_indexes: bool = True,
        enable_all_index: bool = False,
        scan_page_size: int = 500,
        max_scan: int = 5000,
    ):
        self.url = url
        self.prefix = prefix.rstrip(":")
        self.ttl = ttl
        self.enable_indexes = enable_indexes
        self.enable_all_index = enable_all_index
        self.scan_page_size = scan_page_size
        self.max_scan = max_scan
        self._client = None

    async def _get_client(self):
        if self._client is None:
            if redis is None:
                raise RuntimeError("redis.asyncio not installed; pip install redis>=4.5")
            self._client = redis.from_url(self.url, decode_responses=True)
        return self._client

    # Key helpers
    def _data_key(self, token: str) -> str:
        return f"{self.prefix}:data:{token}"

    def _client_index_key(self, client_id: str) -> str:
        return f"{self.prefix}:client:{client_id}"

    def _owner_index_key(self, owner_id: str) -> str:
        return f"{self.prefix}:owner:{owner_id}"

    def _all_key(self) -> str:
        return f"{self.prefix}:all"

    async def store(self, token: str, data: TokenData) -> None:
        client = await self._get_client()
        key = self._data_key(token)
        await client.set(key, data.to_json(), ex=self.ttl)
        if self.enable_indexes:
            pipe = client.pipeline()
            if data.client_id:
                pipe.sadd(self._client_index_key(data.client_id), token)
            if data.owner_id:
                pipe.sadd(self._owner_index_key(data.owner_id), token)
            if self.enable_all_index:
                pipe.sadd(self._all_key(), token)
            await pipe.execute()
        logger.debug("Stored token %s", token)

    async def get(self, token: str) -> Optional[TokenData]:
        client = await self._get_client()
        raw = await client.get(self._data_key(token))
        if not raw:
            return None
        try:
            return TokenData.from_json(raw)
        except Exception as e:  # pragma: no cover
            logger.error(f"Decode failure: {e}")
            return None

    async def delete(self, token: str) -> bool:
        client = await self._get_client()
        key = self._data_key(token)
        data = None
        if self.enable_indexes:
            raw = await client.get(key)
            if raw:
                try:
                    data = TokenData.from_json(raw)
                except Exception:
                    pass
        removed = (await client.delete(key)) == 1
        if removed and self.enable_indexes and data:
            pipe = client.pipeline()
            if data.client_id:
                pipe.srem(self._client_index_key(data.client_id), token)
            if data.owner_id:
                pipe.srem(self._owner_index_key(data.owner_id), token)
            if self.enable_all_index:
                pipe.srem(self._all_key(), token)
            await pipe.execute()
        return removed

    async def cleanup(self) -> int:
        # TTL-based; optionally remove dangling index entries (lazy approach)
        if not self.enable_indexes:
            return 0
        # Simple heuristic: sample from all index if enabled_all_index
        if not self.enable_all_index:
            return 0
        client = await self._get_client()
        removed = 0
        members = await client.smembers(self._all_key())
        if not members:
            return 0
        pipe = client.pipeline()
        for token in list(members)[:100]:  # cap work
            pipe.exists(self._data_key(token))
        exists_flags = await pipe.execute()
        stale = [t for t, ex in zip(list(members)[:100], exists_flags) if ex == 0]
        if stale:
            pipe = client.pipeline()
            for t in stale:
                pipe.srem(self._all_key(), t)
            await pipe.execute()
            removed = len(stale)
        return removed

    async def exists(self, token: str) -> bool:
        client = await self._get_client()
        return await client.exists(self._data_key(token)) == 1

    async def is_valid(self, token: str) -> bool:
        data = await self.get(token)
        return bool(data and data.is_valid())

    # Index-related methods return empty due to missing secondary structures
    async def get_tokens_by_client(self, client_id: str):
        if not self.enable_indexes:
            return []
        client = await self._get_client()
        tokens = await client.smembers(self._client_index_key(client_id))
        return await self._multi_get(tokens)

    async def get_tokens_by_owner(self, owner_id: str):
        if not self.enable_indexes:
            return []
        client = await self._get_client()
        tokens = await client.smembers(self._owner_index_key(owner_id))
        return await self._multi_get(tokens)

    async def count_tokens(self) -> int:
        if self.enable_all_index and self.enable_indexes:
            client = await self._get_client()
            return await client.scard(self._all_key())
        # Fallback: approximate via SCAN (limited)
        return await self._scan_count()

    async def count_valid_tokens(self) -> int:
        # Approximate: iterate limited number of tokens and count valid
        tokens = await self.get_all_tokens(limit=self.max_scan)
        return sum(1 for t in tokens if t.is_valid())

    async def get_all_tokens(self, limit: Optional[int] = None):
        return await self._scan_tokens(limit=limit)

    async def clear(self) -> int:
        client = await self._get_client()
        # Danger: Only clear keys with our prefix:data:
        pattern = f"{self.prefix}:data:*"
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = await client.scan(cursor=cursor, match=pattern, count=self.scan_page_size)
            if keys:
                deleted += await client.delete(*keys)
            if cursor == 0:
                break
            if deleted >= self.max_scan:
                break
        if self.enable_indexes:
            # Clear index sets (best effort)
            if self.enable_all_index:
                await client.delete(self._all_key())
        return deleted

    async def get_statistics(self):
        total = await self.count_tokens()
        valid = await self.count_valid_tokens()
        return {
            "redis": True,
            "indexed": self.enable_indexes,
            "all_index": self.enable_all_index,
            "total_tokens": total,
            "valid_tokens": valid,
        }

    async def get_tokens_expiring_soon(self, threshold: timedelta = timedelta(minutes=5)):
        now = datetime.utcnow()
        tokens = await self.get_all_tokens(limit=self.max_scan)
        soon: List[TokenData] = []
        for t in tokens:
            if (t.valid_until - now) <= threshold and t.is_valid():
                soon.append(t)
        return soon

    async def revoke(self, token: str) -> bool:
        data = await self.get(token)
        if not data:
            return False
        data.status = TokenStatus.REVOKED
        await self.store(token, data)
        return True

    # Internal helper methods
    async def _multi_get(self, tokens: Iterable[str]) -> List[TokenData]:
        client = await self._get_client()
        pipe = client.pipeline()
        tlist = list(tokens)
        for tok in tlist:
            pipe.get(self._data_key(tok))
        raw_items = await pipe.execute()
        results: List[TokenData] = []
        for raw in raw_items:
            if raw:
                try:
                    results.append(TokenData.from_json(raw))
                except Exception:
                    pass
        return results

    async def _scan_tokens(self, limit: Optional[int] = None) -> List[TokenData]:
        client = await self._get_client()
        pattern = f"{self.prefix}:data:*"
        cursor = 0
        out: List[TokenData] = []
        cap = limit or self.max_scan
        while True:
            cursor, keys = await client.scan(cursor=cursor, match=pattern, count=self.scan_page_size)
            if keys:
                pipe = client.pipeline()
                for k in keys:
                    pipe.get(k)
                raws = await pipe.execute()
                for raw in raws:
                    if raw:
                        try:
                            out.append(TokenData.from_json(raw))
                        except Exception:
                            pass
                if len(out) >= cap:
                    break
            if cursor == 0:
                break
        return out[:cap]

    async def _scan_count(self) -> int:
        client = await self._get_client()
        pattern = f"{self.prefix}:data:*"
        cursor = 0
        count = 0
        while True:
            cursor, keys = await client.scan(cursor=cursor, match=pattern, count=self.scan_page_size)
            count += len(keys)
            if cursor == 0 or count >= self.max_scan:
                break
        return count

__all__ = ["RedisTokenStore"]