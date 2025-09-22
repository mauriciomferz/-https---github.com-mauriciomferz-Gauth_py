"""
Core types and functions for attestation chains.
"""

import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


class RevocationStatus(Enum):
    """Revocation status of a particular payload digest or key."""
    UNKNOWN = 0  # Backend could not determine status (treat conservatively)
    ACTIVE = 1   # Item is currently valid / not revoked
    REVOKED = 2  # Item is revoked and should fail validation


@dataclass
class RevocationCheckTarget:
    """Specifies what is being checked for revocation."""
    payload_digest: str = ""  # Hex digest of a signed link payload
    key_id: str = ""         # Signing key identifier (optional if checking at key granularity)


class RevocationProvider:
    """Interface for revocation backends (CRL, OCSP-like, transparency log, etc.)."""
    
    def check(self, target: RevocationCheckTarget) -> tuple[RevocationStatus, Optional[Exception]]:
        """Return the revocation status for the provided target."""
        raise NotImplementedError


@dataclass
class LinkPayload:
    """Represents the unsigned content for a delegation link.
    Fields intentionally mirror the cross-language design (see ATTESTATION_DESIGN.md).
    """
    subject: str
    scopes: List[str]
    issued_at: int
    expires_at: int
    audience: str
    depth: int
    nonce: str
    version: int
    parent_digest: str = ""
    jurisdiction: str = ""
    constraints: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.constraints is None:
            self.constraints = {}


@dataclass 
class SignedLink:
    """A cryptographically signed attestation link."""
    payload: LinkPayload
    payload_digest: str
    signature: str
    key_id: str


# Type alias for chain
Chain = List[SignedLink]


@dataclass
class KeyPair:
    """Wraps an ed25519 key pair."""
    public: Ed25519PublicKey
    private: Ed25519PrivateKey
    key_id: str


@dataclass
class ChainResult:
    """Synthesizes useful derived attributes from a verified chain.
    It intentionally avoids embedding full links to keep the object lightweight for
    downstream authorization / caching layers.
    """
    root_subject: str      # subject of the root link
    leaf_subject: str      # subject of the terminal (leaf) link
    effective_scopes: List[str]  # intersection of scopes across all links
    depth: int             # depth of the chain (leaf depth)
    earliest_issue: int    # root issued_at
    latest_expiry: int     # minimum (tightest) expiry across links
    chain_valid_at: int    # time used for temporal validation


@dataclass
class VerificationOptions:
    """Holds configurable behaviors for chain verification."""
    now_func: Callable[[], float] = field(default_factory=lambda: time.time)
    revocation_provider: Optional[RevocationProvider] = None
    fail_on_revocation_unknown: bool = False
    max_depth: int = 0  # 0 means no limit


# Metrics counters (thread-safe)
_metrics_lock = threading.Lock()
_metric_verified_chains = 0
_metric_verify_failures = 0
_metric_revoked = 0


def new_key_pair() -> KeyPair:
    """Generate a new ed25519 key pair with a simple time-based key ID."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Generate key ID: attest-<date>-<first4hex>
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    digest = hashlib.sha256(public_bytes).hexdigest()
    key_id = f"attest-{time.strftime('%Y%m%d')}-{digest[:8]}"
    
    return KeyPair(public=public_key, private=private_key, key_id=key_id)


def canonical_json(payload: LinkPayload) -> bytes:
    """Return a deterministic JSON encoding (sorted keys for Constraints + Scopes sorted)."""
    # Create a copy to avoid modifying the original
    data = asdict(payload)
    
    # Sort scopes
    if data.get('scopes'):
        data['scopes'] = sorted(data['scopes'])
    
    # Sort constraints if present
    if data.get('constraints'):
        # Convert to sorted dict
        data['constraints'] = dict(sorted(data['constraints'].items()))
    
    # Convert field names to match JSON format (snake_case to camelCase where needed)
    json_data = {
        'parent_digest': data.get('parent_digest', ''),
        'subject': data['subject'],
        'scopes': data['scopes'],
        'issued_at': data['issued_at'],
        'expires_at': data['expires_at'],
        'audience': data['audience'],
        'jurisdiction': data.get('jurisdiction', ''),
        'depth': data['depth'],
        'constraints': data.get('constraints'),
        'nonce': data['nonce'],
        'version': data['version'],
    }
    
    # Remove empty optional fields to match Go behavior
    if not json_data['parent_digest']:
        del json_data['parent_digest']
    if not json_data['jurisdiction']:
        del json_data['jurisdiction']
    if not json_data['constraints']:
        del json_data['constraints']
    
    return json.dumps(json_data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(payload: LinkPayload) -> tuple[str, bytes]:
    """Return hex-encoded SHA-256 of the canonical JSON."""
    canonical_bytes = canonical_json(payload)
    hash_digest = hashlib.sha256(canonical_bytes).hexdigest()
    return hash_digest, canonical_bytes


def sign_link(payload: LinkPayload, key_pair: KeyPair) -> SignedLink:
    """Produce a SignedLink using the provided key."""
    if key_pair is None:
        raise ValueError("nil key pair")
    
    payload_digest, _ = digest(payload)
    signature_bytes = key_pair.private.sign(payload_digest.encode('utf-8'))
    signature_hex = signature_bytes.hex()
    
    return SignedLink(
        payload=payload,
        payload_digest=payload_digest,
        signature=signature_hex,
        key_id=key_pair.key_id
    )


def verify_link(link: SignedLink, public_key: Ed25519PublicKey) -> None:
    """Verify signature and digest integrity for a single link."""
    # Recompute digest
    computed_digest, _ = digest(link.payload)
    if computed_digest != link.payload_digest:
        raise ValueError("payload digest mismatch")
    
    # Verify signature
    try:
        signature_bytes = bytes.fromhex(link.signature)
        public_key.verify(signature_bytes, link.payload_digest.encode('utf-8'))
    except Exception as e:
        raise ValueError(f"signature verification failed: {e}")


def verify_chain(chain: Chain, key_resolver: Callable[[str], Ed25519PublicKey]) -> None:
    """Validate structure & cryptographic linkage of a chain.
    Remains for backward compatibility; delegates to verify_chain_with_options with defaults.
    """
    verify_chain_with_options(chain, key_resolver)


def verify_chain_with_options(
    chain: Chain, 
    key_resolver: Callable[[str], Ed25519PublicKey],
    options: Optional[VerificationOptions] = None
) -> None:
    """Validate chain structure, signatures, temporal bounds, and optional revocation."""
    global _metric_verified_chains, _metric_verify_failures, _metric_revoked
    
    if not chain:
        raise ValueError("empty chain")
    
    if options is None:
        options = VerificationOptions()
    
    for i, link in enumerate(chain):
        try:
            public_key = key_resolver(link.key_id)
            verify_link(link, public_key)
        except Exception as e:
            with _metrics_lock:
                _metric_verify_failures += 1
            raise e
        
        # Parent digest linkage and scope narrowing
        if i == 0:
            if link.payload.parent_digest:
                raise ValueError("root should not have parent digest")
            if link.payload.depth != 1:
                raise ValueError("root depth must be 1")
        else:
            prev = chain[i-1]
            if link.payload.parent_digest != prev.payload_digest:
                with _metrics_lock:
                    _metric_verify_failures += 1
                raise ValueError("parent digest mismatch")
            if link.payload.depth != prev.payload.depth + 1:
                with _metrics_lock:
                    _metric_verify_failures += 1
                raise ValueError("depth mismatch")
            if not _is_subset(link.payload.scopes, prev.payload.scopes):
                with _metrics_lock:
                    _metric_verify_failures += 1
                raise ValueError("scope widening detected")
        
        # Temporal bounds
        now_unix = int(options.now_func())
        if not (link.payload.issued_at <= now_unix < link.payload.expires_at):
            with _metrics_lock:
                _metric_verify_failures += 1
            raise ValueError("temporal bounds invalid")
        
        # Revocation check
        if options.revocation_provider:
            target = RevocationCheckTarget(
                payload_digest=link.payload_digest,
                key_id=link.key_id
            )
            status, err = options.revocation_provider.check(target)
            if err:
                raise err
            
            if status == RevocationStatus.REVOKED:
                with _metrics_lock:
                    _metric_revoked += 1
                    _metric_verify_failures += 1
                raise ValueError("revoked link")
            elif status == RevocationStatus.UNKNOWN and options.fail_on_revocation_unknown:
                with _metrics_lock:
                    _metric_verify_failures += 1
                raise ValueError("revocation status unknown")
        
        # Max depth enforcement
        if options.max_depth > 0 and link.payload.depth > options.max_depth:
            with _metrics_lock:
                _metric_verify_failures += 1
            raise ValueError("max depth exceeded")
    
    with _metrics_lock:
        _metric_verified_chains += 1


def evaluate_chain(
    chain: Chain,
    key_resolver: Callable[[str], Ed25519PublicKey],
    options: Optional[VerificationOptions] = None
) -> ChainResult:
    """Verify the chain and return a synthesized ChainResult."""
    if not chain:
        raise ValueError("empty chain")
    
    # Verify first
    verify_chain_with_options(chain, key_resolver, options)
    
    if options is None:
        options = VerificationOptions()
    
    now_unix = int(options.now_func())
    
    root = chain[0]
    leaf = chain[-1]
    
    # Intersection of scopes (start with root scopes set then intersect)
    eff_set = set(root.payload.scopes)
    for link in chain[1:]:
        eff_set &= set(link.payload.scopes)
    
    effective_scopes = sorted(list(eff_set))
    
    # Latest expiry is min of all expiries
    latest_expiry = min(link.payload.expires_at for link in chain)
    
    return ChainResult(
        root_subject=root.payload.subject,
        leaf_subject=leaf.payload.subject,
        effective_scopes=effective_scopes,
        depth=leaf.payload.depth,
        earliest_issue=root.payload.issued_at,
        latest_expiry=latest_expiry,
        chain_valid_at=now_unix
    )


def _is_subset(a: List[str], b: List[str]) -> bool:
    """Check if list a is a subset of list b."""
    b_set = set(b)
    return all(item in b_set for item in a)


def snapshot_metrics() -> Dict[str, int]:
    """Return current attestation metric counters."""
    with _metrics_lock:
        return {
            "chains_verified_total": _metric_verified_chains,
            "chain_verify_fail_total": _metric_verify_failures,
            "chain_revoked_total": _metric_revoked,
        }