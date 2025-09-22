import pytest
from datetime import datetime, timedelta

from gauth.token.delegation import (
    DelegationLink,
    DelegationVerifier,
    DelegationPolicy,
    DelegationVerificationError,
)


def make_link(idx: int, subject: str = "user", scope=None, parent=None):
    scope = scope or ["read", "write"]
    return DelegationLink(
        token_id=f"t{idx}",
        subject=subject,
        scope=scope,
        issued_at=datetime.utcnow() - timedelta(minutes=idx),
        parent_id=parent,
    )


def test_delegation_success():
    chain = [
        make_link(0, scope=["read", "write", "delete"]),
        make_link(1, scope=["read", "write"], parent="t0"),
        make_link(2, scope=["read"], parent="t1"),
    ]
    info = DelegationVerifier().verify(chain)
    assert info.depth == 3
    assert info.scopes_intersection() == ["read"]


def test_delegation_depth_exceeded():
    policy = DelegationPolicy(max_depth=2)
    chain = [make_link(0), make_link(1, parent="t0"), make_link(2, parent="t1")]
    with pytest.raises(DelegationVerificationError):
        DelegationVerifier(policy).verify(chain)


def test_scope_narrowing_violation():
    chain = [
        make_link(0, scope=["read", "write"]),
        make_link(1, scope=["read", "write", "delete"], parent="t0"),  # broadens
    ]
    with pytest.raises(DelegationVerificationError):
        DelegationVerifier().verify(chain)


def test_subject_continuity_failure():
    chain = [make_link(0, subject="user1"), make_link(1, subject="user2", parent="t0")]
    with pytest.raises(DelegationVerificationError):
        DelegationVerifier().verify(chain)


def test_subject_continuity_disabled():
    policy = DelegationPolicy(enforce_subject_continuity=False)
    chain = [make_link(0, subject="u1"), make_link(1, subject="u2", parent="t0")]
    # Should pass because continuity disabled
    info = DelegationVerifier(policy).verify(chain)
    assert info.depth == 2
