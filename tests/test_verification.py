import pytest
from datetime import datetime, timedelta

from gauth.auth.verification import verify_token_data
from gauth.auth.types import TokenData


def make_token(**overrides):
    base = dict(
        subject="user",
        issuer="issuer",
        audience=["api"],
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        issued_at=datetime.utcnow() - timedelta(minutes=1),
        not_before=datetime.utcnow() - timedelta(minutes=1),
        scope="read write",
        claims={"tier": "gold", "sub": "user"},
    )
    base.update(overrides)
    return TokenData(**base)


def test_verification_success():
    td = make_token()
    outcome = verify_token_data(td, expected_audiences=["api"], required_scopes=["read"], required_claims={"tier": "gold"})
    assert outcome.valid
    assert not outcome.errors


def test_expired():
    td = make_token(expires_at=datetime.utcnow() - timedelta(minutes=10))
    outcome = verify_token_data(td)
    assert not outcome.valid
    assert any("expired" in e for e in outcome.errors)


def test_not_yet_valid():
    td = make_token(not_before=datetime.utcnow() + timedelta(minutes=10))
    outcome = verify_token_data(td)
    assert not outcome.valid
    assert any("not_yet_valid" in e for e in outcome.errors)


def test_audience_mismatch():
    td = make_token(audience=["other"])
    outcome = verify_token_data(td, expected_audiences=["api"])  # require api
    assert not outcome.valid
    assert any("audience_mismatch" in e for e in outcome.errors)


def test_missing_scopes():
    td = make_token(scope="read")
    outcome = verify_token_data(td, required_scopes=["read", "write"])  # missing write
    assert not outcome.valid
    assert any("missing_scopes" in e for e in outcome.errors)


def test_claim_mismatch():
    td = make_token()
    outcome = verify_token_data(td, required_claims={"tier": "platinum"})
    assert not outcome.valid
    assert any("claim_mismatch:tier" in e for e in outcome.errors)


def test_missing_claim():
    td = make_token()
    outcome = verify_token_data(td, required_claims={"region": "us"})
    assert not outcome.valid
    assert any("missing_claim:region" in e for e in outcome.errors)
