"""Signing key rotation manager (stub implementation)."""

from __future__ import annotations

import asyncio
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional


class KeyStatus(str, Enum):
    ACTIVE = "active"
    GRACE = "grace"
    RETIRED = "retired"


@dataclass
class RotationPolicy:
    rotation_interval: timedelta = timedelta(hours=12)
    grace_period: timedelta = timedelta(hours=24)
    max_active_keys: int = 3


@dataclass
class KeyRecord:
    key_id: str
    secret: bytes
    created_at: datetime
    status: KeyStatus
    not_before: datetime
    expires_at: datetime

    def is_usable(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.status in {KeyStatus.ACTIVE, KeyStatus.GRACE} and self.not_before <= now < self.expires_at:
            return True
        return False


class RotationManager:
    """Manage signing key rotation with grace overlap."""

    def __init__(self, policy: Optional[RotationPolicy] = None):
        self.policy = policy or RotationPolicy()
        self._lock = asyncio.Lock()
        self._keys: Dict[str, KeyRecord] = {}
        self._active_key_id: Optional[str] = None

    async def initialize(self) -> None:
        async with self._lock:
            if not self._active_key_id:
                record = self._generate_new_key(status=KeyStatus.ACTIVE)
                self._keys[record.key_id] = record
                self._active_key_id = record.key_id

    def _generate_new_key(self, status: KeyStatus) -> KeyRecord:
        now = datetime.now(timezone.utc)
        key_id = secrets.token_hex(8)
        secret = os.urandom(32)
        expires_at = now + self.policy.rotation_interval + self.policy.grace_period
        return KeyRecord(
            key_id=key_id,
            secret=secret,
            created_at=now,
            status=status,
            not_before=now,
            expires_at=expires_at,
        )

    async def rotate_if_needed(self) -> Optional[KeyRecord]:
        async with self._lock:
            if not self._active_key_id:
                return None
            active = self._keys[self._active_key_id]
            now = datetime.now(timezone.utc)
            if now - active.created_at >= self.policy.rotation_interval:
                # Demote current active to grace
                active.status = KeyStatus.GRACE
                # Generate new active
                new_rec = self._generate_new_key(status=KeyStatus.ACTIVE)
                self._keys[new_rec.key_id] = new_rec
                self._active_key_id = new_rec.key_id
                # Retire and prune
                self._prune(now)
                return new_rec
            return None

    async def force_rotate(self) -> KeyRecord:
        async with self._lock:
            if self._active_key_id:
                self._keys[self._active_key_id].status = KeyStatus.GRACE
            new_rec = self._generate_new_key(status=KeyStatus.ACTIVE)
            self._keys[new_rec.key_id] = new_rec
            self._active_key_id = new_rec.key_id
            self._prune(datetime.now(timezone.utc))
            return new_rec

    def _prune(self, now: datetime) -> None:
        # Retire expired grace keys
        for kid, rec in list(self._keys.items()):
            if rec.status == KeyStatus.GRACE and now >= rec.expires_at:
                rec.status = KeyStatus.RETIRED
        # Enforce max active/grace keys by dropping oldest retired ones
        # (lightweight; optional future persistence ordering)
        usable = [r for r in self._keys.values() if r.status != KeyStatus.RETIRED]
        if len(usable) > self.policy.max_active_keys:
            # Sort by created_at asc and retire earliest beyond cap
            for rec in sorted(usable, key=lambda r: r.created_at)[:-self.policy.max_active_keys]:
                rec.status = KeyStatus.RETIRED

    def get_active_key(self) -> Optional[KeyRecord]:
        if not self._active_key_id:
            return None
        return self._keys.get(self._active_key_id)

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)

    async def list_keys(self) -> List[KeyRecord]:
        return list(self._keys.values())

    async def cleanup(self) -> None:
        # Optional explicit cleanup hook (noop for now)
        pass

    async def expire_grace_keys(self) -> int:
        """Force-expire all grace keys (test utility).

        Returns number of keys transitioned to RETIRED.
        """
        now = datetime.now(timezone.utc)
        count = 0
        for rec in self._keys.values():
            if rec.status == KeyStatus.GRACE:
                rec.expires_at = now - timedelta(seconds=1)
        self._prune(now)
        for rec in self._keys.values():
            if rec.status == KeyStatus.RETIRED:
                count += 1
        return count


__all__ = [
    "RotationManager",
    "RotationPolicy",
    "KeyRecord",
    "KeyStatus",
]