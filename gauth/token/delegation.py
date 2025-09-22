"""Delegation & attestation scaffold.

Provides basic structures for delegated tokens (parent chain) and a simple
verifier that enforces:
- Max delegation depth
- Required parent subject continuity (optional)
- Scope narrowing (child scope must be subset of parent)

Future enhancements:
- Attestation proofs (cryptographic)
- Policy-based delegation constraints
- Revocation propagation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class DelegationLink:
    token_id: str
    subject: str
    scope: List[str]
    issued_at: datetime
    parent_id: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DelegatedTokenInfo:
    chain: List[DelegationLink]
    depth: int

    def scopes_intersection(self) -> List[str]:
        if not self.chain:
            return []
        allowed = set(self.chain[0].scope)
        for link in self.chain[1:]:
            allowed &= set(link.scope)
        return sorted(allowed)


class DelegationVerificationError(Exception):
    pass


@dataclass
class DelegationPolicy:
    max_depth: int = 3
    enforce_subject_continuity: bool = True
    enforce_scope_narrowing: bool = True


class DelegationVerifier:
    def __init__(self, policy: Optional[DelegationPolicy] = None):
        self.policy = policy or DelegationPolicy()

    def verify(self, chain: List[DelegationLink]) -> DelegatedTokenInfo:
        if not chain:
            raise DelegationVerificationError("empty_delegation_chain")
        if len(chain) > self.policy.max_depth:
            raise DelegationVerificationError("delegation_depth_exceeded")
        if self.policy.enforce_subject_continuity:
            for i in range(1, len(chain)):
                if chain[i].subject != chain[i-1].subject:
                    raise DelegationVerificationError("subject_continuity_failed")
        if self.policy.enforce_scope_narrowing:
            parent_scopes = set(chain[0].scope)
            for link in chain[1:]:
                if not set(link.scope).issubset(parent_scopes):
                    raise DelegationVerificationError("scope_narrowing_violation")
                parent_scopes = set(link.scope)
        return DelegatedTokenInfo(chain=chain, depth=len(chain))

__all__ = [
    "DelegationLink",
    "DelegatedTokenInfo",
    "DelegationPolicy",
    "DelegationVerifier",
    "DelegationVerificationError",
]
