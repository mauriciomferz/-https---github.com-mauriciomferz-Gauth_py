"""
Package attestation provides cryptographic signing and verification for
delegation (power-of-attorney) chains. It implements Phase 1 of the
attestation roadmap (canonicalization + Ed25519 signing + chain verification).

Future roadmap (see docs/ATTESTATION_DESIGN.md):
  - Revocation list integration
  - PQ / hybrid signature abstraction
  - Transparency log (Merkle tree) hooks
  - Metrics & audit linkage
"""

from .types import (
    LinkPayload,
    SignedLink,
    Chain,
    KeyPair,
    ChainResult,
    RevocationStatus,
    RevocationCheckTarget,
    RevocationProvider,
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
)

from .revocation import (
    NoopRevocationProvider,
    InMemoryRevocationProvider,
)

__all__ = [
    'LinkPayload',
    'SignedLink', 
    'Chain',
    'KeyPair',
    'ChainResult',
    'RevocationStatus',
    'RevocationCheckTarget',
    'RevocationProvider',
    'VerificationOptions',
    'canonical_json',
    'digest',
    'sign_link',
    'verify_link',
    'verify_chain',
    'verify_chain_with_options',
    'evaluate_chain',
    'snapshot_metrics',
    'new_key_pair',
    'NoopRevocationProvider',
    'InMemoryRevocationProvider',
]