"""Token verification helper utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any

from .types import TokenData, ValidationResult, TokenValidationConfig


@dataclass
class VerificationOutcome:
    valid: bool
    errors: List[str]
    warnings: List[str]


def _ensure_list(aud: Optional[Union[str, List[str]]]) -> List[str]:
    if aud is None:
        return []
    if isinstance(aud, str):
        return [aud]
    return aud


def verify_token_data(
    token_data: TokenData,
    config: Optional[TokenValidationConfig] = None,
    expected_audiences: Optional[List[str]] = None,
    required_scopes: Optional[List[str]] = None,
    required_claims: Optional[Dict[str, Any]] = None,
    clock_skew: timedelta = timedelta(seconds=300),
) -> VerificationOutcome:
    """Perform extended verification on TokenData beyond signature.

    Args:
        token_data: Parsed token data
        config: Optional validation config
        expected_audiences: Audiences any-of that must match (overrides config if provided)
        required_scopes: Scopes all-of that must be present (overrides config if provided)
        required_claims: Dict of claim_name->expected_value (exact match)
        clock_skew: Allowed clock skew window
    Returns:
        VerificationOutcome summarizing validity and issues.
    """
    errors: List[str] = []
    warnings: List[str] = []

    now = datetime.utcnow()

    # Expiration
    if token_data.expires_at and now > (token_data.expires_at + clock_skew):
        errors.append("expired")

    # Not before
    if token_data.not_before and now < (token_data.not_before - clock_skew):
        errors.append("not_yet_valid")

    # Audience
    expected = expected_audiences or (config.allowed_audiences if config else [])
    if expected:
        token_aud = _ensure_list(token_data.audience)
        if not any(a in token_aud for a in expected):
            errors.append("audience_mismatch")

    # Scopes
    req_scopes = required_scopes or (config.required_scopes if config else [])
    if req_scopes:
        token_scopes = (token_data.scope or "").split()
        missing = [s for s in req_scopes if s not in token_scopes]
        if missing:
            errors.append(f"missing_scopes:{','.join(missing)}")

    # Required claims
    if required_claims:
        for k, v in required_claims.items():
            if k not in token_data.claims:
                errors.append(f"missing_claim:{k}")
            elif v is not None and token_data.claims.get(k) != v:
                errors.append(f"claim_mismatch:{k}")

    # Issued at sanity (warn, not error)
    if token_data.issued_at and token_data.expires_at:
        if token_data.issued_at > token_data.expires_at:
            warnings.append("issued_after_expiry")

    return VerificationOutcome(valid=not errors, errors=errors, warnings=warnings)


def to_validation_result(outcome: VerificationOutcome, token_data: TokenData) -> ValidationResult:
    if outcome.valid:
        return ValidationResult(valid=True, token_data=token_data)
    # Combine errors into message
    return ValidationResult(
        valid=False,
        token_data=token_data,
        error_message=";".join(outcome.errors),
        error_code="VERIFICATION_FAILED",
    )


__all__ = [
    "verify_token_data",
    "VerificationOutcome",
    "to_validation_result",
]