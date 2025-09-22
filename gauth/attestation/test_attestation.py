"""
Tests for attestation package.
"""

import pytest
import time
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gauth.attestation import (
    LinkPayload,
    SignedLink,
    Chain,
    KeyPair,
    ChainResult,
    RevocationStatus,
    RevocationCheckTarget,
    VerificationOptions,
    canonical_json,
    digest,
    sign_link,
    verify_link,
    verify_chain,
    verify_chain_with_options,
    evaluate_chain,
    snapshot_metrics,
    new_key_pair,
    NoopRevocationProvider,
    InMemoryRevocationProvider,
)


def make_payload(subject: str, scopes: list[str], depth: int, parent: str = "") -> LinkPayload:
    """Helper to create test payloads."""
    now = int(time.time())
    return LinkPayload(
        parent_digest=parent,
        subject=subject,
        scopes=scopes,
        issued_at=now - 1,
        expires_at=now + 300,  # 5 minutes
        audience="api",
        depth=depth,
        nonce="abcd1234",
        version=1,
    )


class TestCanonicalJSON:
    """Test canonical JSON encoding."""
    
    def test_determinism(self):
        """Test that canonical JSON is deterministic."""
        payload = make_payload("alice", ["write", "read"], 1)
        d1, b1 = digest(payload)
        d2, b2 = digest(payload)
        assert d1 == d2
        assert b1 == b2
    
    def test_scope_sorting(self):
        """Test that scopes are sorted in canonical JSON."""
        payload = make_payload("alice", ["write", "read", "admin"], 1)
        canonical_bytes = canonical_json(payload)
        canonical_str = canonical_bytes.decode('utf-8')
        # Should have scopes sorted as ["admin", "read", "write"]
        assert '"scopes":["admin","read","write"]' in canonical_str


class TestKeyPair:
    """Test key pair generation."""
    
    def test_key_generation(self):
        """Test that key pairs are generated correctly."""
        kp = new_key_pair()
        assert isinstance(kp, KeyPair)
        assert isinstance(kp.public, Ed25519PublicKey)
        assert kp.key_id.startswith("attest-")
        assert len(kp.key_id.split("-")) == 3  # attest-YYYYMMDD-hexdigits


class TestSigning:
    """Test signing and verification."""
    
    def test_sign_and_verify_single(self):
        """Test signing and verifying a single link."""
        kp = new_key_pair()
        payload = make_payload("bob", ["read"], 1)
        
        link = sign_link(payload, kp)
        assert isinstance(link, SignedLink)
        assert link.key_id == kp.key_id
        
        # Should verify successfully
        verify_link(link, kp.public)
        
        # Tamper with payload and verification should fail
        link.payload.subject = "mallory"
        with pytest.raises(ValueError, match="payload digest mismatch"):
            verify_link(link, kp.public)
    
    def test_invalid_digest(self):
        """Test verification with corrupted digest."""
        kp = new_key_pair()
        payload = make_payload("dave", ["read"], 1)
        link = sign_link(payload, kp)
        
        # Corrupt digest
        digest_bytes = bytes.fromhex(link.payload_digest)
        if digest_bytes:
            corrupted = bytearray(digest_bytes)
            corrupted[0] ^= 0xff
            link.payload_digest = corrupted.hex()
        
        with pytest.raises(ValueError, match="payload digest mismatch"):
            verify_link(link, kp.public)


class TestChainVerification:
    """Test chain verification."""
    
    def test_verify_chain(self):
        """Test basic chain verification."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create root link
        root_payload = make_payload("carol", ["read", "write"], 1)
        root_link = sign_link(root_payload, kp)
        
        # Create child link
        child_payload = make_payload("carol", ["read"], 2, root_link.payload_digest)
        child_link = sign_link(child_payload, kp)
        
        chain = [root_link, child_link]
        
        # Should verify successfully
        verify_chain(chain, resolve)
    
    def test_scope_widening_attack(self):
        """Test that scope widening is detected."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create root with limited scopes
        root_payload = make_payload("carol", ["read"], 1)
        root_link = sign_link(root_payload, kp)
        
        # Try to create child with more scopes (should fail)
        child_payload = make_payload("carol", ["read", "write"], 2, root_link.payload_digest)
        child_link = sign_link(child_payload, kp)
        
        chain = [root_link, child_link]
        
        with pytest.raises(ValueError, match="scope widening detected"):
            verify_chain(chain, resolve)
    
    def test_empty_chain(self):
        """Test that empty chains are rejected."""
        def resolve(key_id: str) -> Ed25519PublicKey:
            return new_key_pair().public
        
        with pytest.raises(ValueError, match="empty chain"):
            verify_chain([], resolve)
    
    def test_root_validation(self):
        """Test root link validation rules."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Root with parent digest should fail
        root_payload = make_payload("alice", ["read"], 1, "someparent")
        root_link = sign_link(root_payload, kp)
        
        with pytest.raises(ValueError, match="root should not have parent digest"):
            verify_chain([root_link], resolve)
        
        # Root with wrong depth should fail
        root_payload = make_payload("alice", ["read"], 2)
        root_link = sign_link(root_payload, kp)
        
        with pytest.raises(ValueError, match="root depth must be 1"):
            verify_chain([root_link], resolve)


class TestRevocation:
    """Test revocation providers."""
    
    def test_noop_revocation_provider(self):
        """Test that noop provider always returns active."""
        provider = NoopRevocationProvider()
        target = RevocationCheckTarget(payload_digest="abc")
        status, err = provider.check(target)
        assert status == RevocationStatus.ACTIVE
        assert err is None
    
    def test_in_memory_revocation_provider(self):
        """Test in-memory revocation provider."""
        provider = InMemoryRevocationProvider(default_unknown=False)
        
        # Should be active by default
        target = RevocationCheckTarget(payload_digest="abc")
        status, err = provider.check(target)
        assert status == RevocationStatus.ACTIVE
        assert err is None
        
        # Revoke digest
        provider.revoke_digest("abc")
        status, err = provider.check(target)
        assert status == RevocationStatus.REVOKED
        assert err is None
        
        # Unrevoke digest
        provider.unrevoke_digest("abc")
        status, err = provider.check(target)
        assert status == RevocationStatus.ACTIVE
        assert err is None
        
        # Test key revocation
        target = RevocationCheckTarget(key_id="key123")
        provider.revoke_key("key123")
        status, err = provider.check(target)
        assert status == RevocationStatus.REVOKED
        assert err is None
    
    def test_revocation_with_chain(self):
        """Test chain verification with revocation."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        payload = make_payload("user", ["read"], 1)
        link = sign_link(payload, kp)
        chain = [link]
        
        # Mock revoked provider
        provider = Mock()
        provider.check.return_value = (RevocationStatus.REVOKED, None)
        
        options = VerificationOptions(revocation_provider=provider)
        
        with pytest.raises(ValueError, match="revoked link"):
            verify_chain_with_options(chain, resolve, options)
    
    def test_revocation_unknown_allowed(self):
        """Test that unknown revocation status is allowed by default."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        payload = make_payload("user", ["read"], 1)
        link = sign_link(payload, kp)
        chain = [link]
        
        # Mock unknown provider
        provider = Mock()
        provider.check.return_value = (RevocationStatus.UNKNOWN, None)
        
        options = VerificationOptions(revocation_provider=provider)
        
        # Should succeed by default
        verify_chain_with_options(chain, resolve, options)
        
        # Should fail when configured to fail on unknown
        options.fail_on_revocation_unknown = True
        with pytest.raises(ValueError, match="revocation status unknown"):
            verify_chain_with_options(chain, resolve, options)


class TestChainEvaluation:
    """Test chain evaluation and result synthesis."""
    
    def test_evaluate_chain(self):
        """Test chain evaluation and result generation."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create a simple chain
        root_payload = make_payload("alice", ["read", "write", "admin"], 1)
        root_link = sign_link(root_payload, kp)
        
        child_payload = make_payload("bob", ["read", "write"], 2, root_link.payload_digest)
        child_link = sign_link(child_payload, kp)
        
        chain = [root_link, child_link]
        result = evaluate_chain(chain, resolve)
        
        assert isinstance(result, ChainResult)
        assert result.root_subject == "alice"
        assert result.leaf_subject == "bob"
        assert result.depth == 2
        assert set(result.effective_scopes) == {"read", "write"}  # Intersection
        assert result.earliest_issue == root_payload.issued_at
        assert result.latest_expiry == min(root_payload.expires_at, child_payload.expires_at)


class TestMetrics:
    """Test metrics collection."""
    
    def test_metrics_snapshot(self):
        """Test that metrics are collected."""
        # Get initial metrics
        initial = snapshot_metrics()
        
        # Perform some operations
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        payload = make_payload("user", ["read"], 1)
        link = sign_link(payload, kp)
        chain = [link]
        
        verify_chain(chain, resolve)
        
        # Check metrics updated
        updated = snapshot_metrics()
        assert updated["chains_verified_total"] > initial["chains_verified_total"]


class TestTemporalValidation:
    """Test temporal bounds validation."""
    
    def test_expired_link(self):
        """Test that expired links are rejected."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create expired payload
        now = int(time.time())
        payload = LinkPayload(
            subject="user",
            scopes=["read"],
            issued_at=now - 3600,  # 1 hour ago
            expires_at=now - 1800,  # 30 minutes ago (expired)
            audience="api",
            depth=1,
            nonce="test",
            version=1,
        )
        
        link = sign_link(payload, kp)
        chain = [link]
        
        with pytest.raises(ValueError, match="temporal bounds invalid"):
            verify_chain(chain, resolve)
    
    def test_future_issued_link(self):
        """Test that future-issued links are rejected."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create future-issued payload
        now = int(time.time())
        payload = LinkPayload(
            subject="user",
            scopes=["read"],
            issued_at=now + 3600,  # 1 hour in the future
            expires_at=now + 7200,  # 2 hours in the future
            audience="api",
            depth=1,
            nonce="test",
            version=1,
        )
        
        link = sign_link(payload, kp)
        chain = [link]
        
        with pytest.raises(ValueError, match="temporal bounds invalid"):
            verify_chain(chain, resolve)


class TestMaxDepth:
    """Test max depth enforcement."""
    
    def test_max_depth_enforcement(self):
        """Test that max depth is enforced."""
        kp = new_key_pair()
        
        def resolve(key_id: str) -> Ed25519PublicKey:
            return kp.public
        
        # Create a chain with depth 2
        root_payload = make_payload("alice", ["read"], 1)
        root_link = sign_link(root_payload, kp)
        
        child_payload = make_payload("bob", ["read"], 2, root_link.payload_digest)
        child_link = sign_link(child_payload, kp)
        
        chain = [root_link, child_link]
        
        # Should succeed with no max depth
        verify_chain(chain, resolve)
        
        # Should succeed with max depth 2
        options = VerificationOptions(max_depth=2)
        verify_chain_with_options(chain, resolve, options)
        
        # Should fail with max depth 1
        options = VerificationOptions(max_depth=1)
        with pytest.raises(ValueError, match="max depth exceeded"):
            verify_chain_with_options(chain, resolve, options)