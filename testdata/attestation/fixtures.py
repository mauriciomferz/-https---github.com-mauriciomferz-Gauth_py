"""
Cross-language parity test fixtures for attestation package.

This script generates canonical JSON fixtures that should match the Go implementation
for testing cross-language compatibility.
"""

import json
import os
import sys
import time

# Add parent directories to path so we can import gauth
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gauth.attestation import LinkPayload, canonical_json, digest


def fixture_payload() -> LinkPayload:
    """Return a deterministic LinkPayload for fixture generation."""
    return LinkPayload(
        parent_digest="",
        subject="fixture-subject",
        scopes=["write", "read", "admin"],
        issued_at=1_700_000_000,  # Fixed timestamp to stay stable
        expires_at=1_700_000_000 + 3600,
        audience="fixture-audience",
        depth=1,
        constraints={
            "tier": "gold",
            "region": "us",
        },
        nonce="0123456789abcdef",
        version=1,
    )


def main():
    """Generate JSON artifacts for cross-language testing."""
    payload = fixture_payload()
    
    # Generate canonical JSON
    canonical_bytes = canonical_json(payload)
    canonical_str = canonical_bytes.decode('utf-8')
    
    # Generate digest
    payload_digest, _ = digest(payload)
    
    # Create output directory if it doesn't exist
    out_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)
    
    # Write canonical JSON fixture
    canonical_file = os.path.join(out_dir, "canonical.json")
    with open(canonical_file, 'w') as f:
        f.write(canonical_str)
    
    # Write digest fixture
    digest_file = os.path.join(out_dir, "digest.txt")
    with open(digest_file, 'w') as f:
        f.write(payload_digest)
    
    # Write summary
    summary = {
        "payload": {
            "subject": payload.subject,
            "scopes": payload.scopes,
            "issued_at": payload.issued_at,
            "expires_at": payload.expires_at,
            "audience": payload.audience,
            "depth": payload.depth,
            "constraints": payload.constraints,
            "nonce": payload.nonce,
            "version": payload.version,
        },
        "canonical_json_length": len(canonical_bytes),
        "digest": payload_digest,
        "generated_at": int(time.time()),
        "python_version": sys.version.split()[0],
    }
    
    summary_file = os.path.join(out_dir, "summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    
    print(f"✅ Generated attestation fixtures:")
    print(f"   📄 Canonical JSON: {canonical_file}")
    print(f"   🔍 Digest: {digest_file}")
    print(f"   📊 Summary: {summary_file}")
    print(f"   🎯 Digest: {payload_digest}")
    print(f"   📏 JSON Length: {len(canonical_bytes)} bytes")


if __name__ == "__main__":
    main()