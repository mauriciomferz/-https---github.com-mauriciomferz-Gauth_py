"""Legal compliance & policy registry for GAuth Python port.

This module provides a lightweight, extensible mechanism for registering
and evaluating compliance / legal / contextual policies during token issuance
and validation flows. It intentionally keeps surface area minimal while
allowing future enrichment (jurisdiction checks, data handling restrictions,
delegation constraints, etc.).

Design goals:
 - Zero hard dependency on external services
 - Composable: multiple policies aggregate into a single evaluation result
 - Transparent diagnostics: each policy returns structured outcome with reason
 - Non-blocking: failures raise explicit exception for caller to decide action

Integration points (initial):
 - AuthService.generate_token (pre-issuance gate)
 - AuthService.validate_token (post-verification gate)

Future extensions:
 - Policy categories (LEGAL, SECURITY, PRIVACY)
 - Policy scoping (per client, per tenant)
 - Caching layer for deterministic policies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, List, Dict, Any, Optional, Iterable
from enum import Enum
import datetime as _dt


class PolicyPhase(Enum):
    """Phase where a policy applies."""
    ISSUANCE = "issuance"
    VALIDATION = "validation"
    BOTH = "both"


@dataclass
class PolicyContext:
    """Context passed to policy evaluators.

    Contains token claims (if available), request attributes, and arbitrary
    metadata supplied by higher layers (e.g., delegation chain summary).
    """
    phase: PolicyPhase
    claims: Dict[str, Any] = field(default_factory=dict)
    request: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    now: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))


@dataclass
class PolicyResult:
    """Outcome of a single policy evaluation."""
    policy: str
    passed: bool
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:  # convenience for logging / JSON
        return {
            "policy": self.policy,
            "passed": self.passed,
            "reason": self.reason,
            "details": self.details,
        }


class Policy(Protocol):
    """Policy interface that all policies must implement."""

    name: str
    phase: PolicyPhase

    def evaluate(self, ctx: PolicyContext) -> PolicyResult:
        ...  # pragma: no cover - interface placeholder


class PolicyViolation(Exception):
    """Raised when one or more policies fail."""

    def __init__(self, failed: List[PolicyResult], passed: List[PolicyResult]):
        self.failed = failed
        self.passed = passed
        message = ", ".join(f"{r.policy}: {r.reason}" for r in failed) or "policy violation"
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failed": [r.to_dict() for r in self.failed],
            "passed": [r.to_dict() for r in self.passed],
        }


class PolicyRegistry:
    """Registry storing policies and coordinating evaluation."""

    def __init__(self):
        self._policies: List[Policy] = []

    def register(self, policy: Policy) -> None:
        # Avoid duplicates by name
        if any(p.name == policy.name for p in self._policies):
            raise ValueError(f"Policy with name '{policy.name}' already registered")
        self._policies.append(policy)

    def list(self, phase: Optional[PolicyPhase] = None) -> List[Policy]:
        if phase is None:
            return list(self._policies)
        return [p for p in self._policies if p.phase in (phase, PolicyPhase.BOTH)]

    def evaluate(self, ctx: PolicyContext) -> List[PolicyResult]:
        applicable = self.list(ctx.phase)
        results: List[PolicyResult] = []
        for policy in applicable:
            try:
                res = policy.evaluate(ctx)
            except Exception as e:  # Defensive: wrap unexpected policy errors
                res = PolicyResult(policy=policy.name, passed=False, reason=f"error: {e}")
            results.append(res)
        return results

    def enforce(self, ctx: PolicyContext) -> List[PolicyResult]:
        results = self.evaluate(ctx)
        failed = [r for r in results if not r.passed]
        if failed:
            raise PolicyViolation(failed=failed, passed=[r for r in results if r.passed])
        return results


# --- Example baseline policies -------------------------------------------------

@dataclass
class ScopeRestrictionPolicy:
    """Ensures that certain forbidden scopes are not requested or present.

    Useful for legal/regional restrictions (e.g., disallow exporting certain data).
    """
    name: str = "scope_restriction"
    phase: PolicyPhase = PolicyPhase.BOTH
    forbidden_scopes: Iterable[str] = field(default_factory=list)

    def evaluate(self, ctx: PolicyContext) -> PolicyResult:
        requested_scopes: List[str] = []
        # From issuance request
        if ctx.request.get("scope"):
            requested_scopes.extend(str(ctx.request.get("scope")).split())
        # From claims (validation path)
        claim_scope = ctx.claims.get("scope")
        if claim_scope:
            requested_scopes.extend(str(claim_scope).split())
        forbidden = set(s.lower() for s in self.forbidden_scopes)
        violations = [s for s in requested_scopes if s.lower() in forbidden]
        if violations:
            return PolicyResult(
                policy=self.name,
                passed=False,
                reason=f"forbidden scopes: {', '.join(sorted(set(violations)))}",
                details={"violations": sorted(set(violations))},
            )
        return PolicyResult(policy=self.name, passed=True)


@dataclass
class JurisdictionPolicy:
    """Ensures token or request is associated with an allowed jurisdiction list.

    Looks at (in order): request['jurisdiction'], claims['jurisdiction'], metadata['jurisdiction'].
    """
    name: str = "jurisdiction_allowlist"
    phase: PolicyPhase = PolicyPhase.BOTH
    allowed_jurisdictions: Iterable[str] = field(default_factory=list)

    def evaluate(self, ctx: PolicyContext) -> PolicyResult:
        allowed = set(j.lower() for j in self.allowed_jurisdictions)
        if not allowed:  # If no constraints, pass
            return PolicyResult(policy=self.name, passed=True)
        jurisdiction = (
            ctx.request.get("jurisdiction")
            or ctx.claims.get("jurisdiction")
            or ctx.metadata.get("jurisdiction")
        )
        # For issuance phase allow omission (caller may add later); only strict during validation
        if jurisdiction is None:
            if ctx.phase == PolicyPhase.ISSUANCE:
                return PolicyResult(policy=self.name, passed=True, reason="deferred")
            return PolicyResult(policy=self.name, passed=False, reason="missing jurisdiction")
        if str(jurisdiction).lower() not in allowed:
            return PolicyResult(policy=self.name, passed=False, reason=f"jurisdiction '{jurisdiction}' not allowed")
        return PolicyResult(policy=self.name, passed=True)


@dataclass
class DelegationDepthPolicy:
    """Ensures the delegation chain depth does not exceed a maximum.

    Expects metadata['delegation_depth'] to be provided by caller if relevant.
    """
    name: str = "delegation_depth"
    phase: PolicyPhase = PolicyPhase.VALIDATION
    max_depth: int = 5

    def evaluate(self, ctx: PolicyContext) -> PolicyResult:
        depth = ctx.metadata.get("delegation_depth")
        if depth is None:
            return PolicyResult(policy=self.name, passed=True)  # Not applicable
        if depth > self.max_depth:
            return PolicyResult(policy=self.name, passed=False, reason=f"delegation depth {depth} > {self.max_depth}")
        return PolicyResult(policy=self.name, passed=True)
        return PolicyResult(policy=self.name, passed=True)


__all__ = [
    "PolicyPhase",
    "PolicyContext",
    "PolicyResult",
    "Policy",
    "PolicyViolation",
    "PolicyRegistry",
    # Baseline policies
    "ScopeRestrictionPolicy",
    "JurisdictionPolicy",
    "DelegationDepthPolicy",
]
