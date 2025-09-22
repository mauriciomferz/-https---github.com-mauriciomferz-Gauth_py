"""
Revocation provider implementations.
"""

import threading
from typing import Dict, Optional
from .types import RevocationProvider, RevocationStatus, RevocationCheckTarget


class NoopRevocationProvider(RevocationProvider):
    """Placeholder implementation always returning RevocationActive."""
    
    def check(self, target: RevocationCheckTarget) -> tuple[RevocationStatus, Optional[Exception]]:
        return RevocationStatus.ACTIVE, None


class InMemoryRevocationProvider(RevocationProvider):
    """Thread-safe revocation provider storing revoked payload digests and key IDs.
    It is suitable for tests or single-process deployments. For distributed use, replace with a shared store.
    """
    
    def __init__(self, default_unknown: bool = False):
        """Create a new provider. If default_unknown is True, missing entries return Unknown; else Active."""
        self._lock = threading.Lock()  # Use basic Lock instead of RWLock
        self._digests: Dict[str, RevocationStatus] = {}  # PayloadDigest -> status
        self._keys: Dict[str, RevocationStatus] = {}     # KeyID -> status
        self._default_unknown = default_unknown
    
    def revoke_digest(self, digest: str) -> None:
        """Mark a payload digest as revoked."""
        with self._lock:
            self._digests[digest] = RevocationStatus.REVOKED
    
    def unrevoke_digest(self, digest: str) -> None:
        """Remove a digest revocation entry."""
        with self._lock:
            self._digests.pop(digest, None)
    
    def revoke_key(self, key_id: str) -> None:
        """Mark a key id as revoked."""
        with self._lock:
            self._keys[key_id] = RevocationStatus.REVOKED
    
    def unrevoke_key(self, key_id: str) -> None:
        """Remove key revocation entry."""
        with self._lock:
            self._keys.pop(key_id, None)
    
    def check(self, target: RevocationCheckTarget) -> tuple[RevocationStatus, Optional[Exception]]:
        """Check revocation status.
        Digest revocation has precedence over key revocation. If neither present returns Active or Unknown depending on policy.
        """
        with self._lock:
            # Check digest first
            if target.payload_digest:
                if target.payload_digest in self._digests:
                    return self._digests[target.payload_digest], None
            
            # Check key
            if target.key_id:
                if target.key_id in self._keys:
                    return self._keys[target.key_id], None
            
            # Default behavior
            if self._default_unknown:
                return RevocationStatus.UNKNOWN, None
            return RevocationStatus.ACTIVE, None