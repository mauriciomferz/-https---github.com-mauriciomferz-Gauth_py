"""
Example: Cryptographic Attestation Chains

This example demonstrates the attestation package functionality:
- Creating Ed25519 key pairs
- Signing delegation links
- Building and verifying attestation chains
- Revocation checking
- Chain evaluation and result synthesis
"""

import sys
import os
import time

# Add parent directory to path so we can import gauth
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gauth.attestation import (
    LinkPayload,
    new_key_pair,
    sign_link,
    verify_chain,
    verify_chain_with_options,
    evaluate_chain,
    InMemoryRevocationProvider,
    VerificationOptions,
    snapshot_metrics,
)


def main():
    print("🔐 GAuth Attestation Chain Demo")
    print("=" * 50)
    
    # Generate key pairs for different entities
    print("\n1. Generating Ed25519 key pairs...")
    alice_keys = new_key_pair()
    bob_keys = new_key_pair()
    carol_keys = new_key_pair()
    
    print(f"   Alice Key ID: {alice_keys.key_id}")
    print(f"   Bob Key ID: {bob_keys.key_id}")
    print(f"   Carol Key ID: {carol_keys.key_id}")
    
    # Create a delegation chain: Alice -> Bob -> Carol
    print("\n2. Creating delegation chain: Alice -> Bob -> Carol")
    
    now = int(time.time())
    
    # Root link: Alice delegates to Bob
    alice_payload = LinkPayload(
        subject="alice@company.com",
        scopes=["read", "write", "admin"],
        issued_at=now - 1,
        expires_at=now + 3600,  # 1 hour
        audience="api.company.com",
        depth=1,
        nonce="alice-root-001",
        version=1,
    )
    
    alice_link = sign_link(alice_payload, alice_keys)
    print(f"   ✓ Alice (root) signed: {alice_link.payload_digest[:16]}...")
    
    # Child link: Bob delegates to Carol (with reduced scopes)
    bob_payload = LinkPayload(
        parent_digest=alice_link.payload_digest,
        subject="bob@company.com", 
        scopes=["read", "write"],  # Narrowed from alice's scopes
        issued_at=now,
        expires_at=now + 1800,  # 30 minutes (shorter than Alice)
        audience="api.company.com",
        depth=2,
        nonce="bob-delegate-001",
        version=1,
    )
    
    bob_link = sign_link(bob_payload, bob_keys)
    print(f"   ✓ Bob (child) signed: {bob_link.payload_digest[:16]}...")
    
    # Leaf link: Carol's final delegation
    carol_payload = LinkPayload(
        parent_digest=bob_link.payload_digest,
        subject="carol@company.com",
        scopes=["read"],  # Further narrowed
        issued_at=now,
        expires_at=now + 900,  # 15 minutes (shortest)
        audience="api.company.com", 
        depth=3,
        nonce="carol-final-001",
        version=1,
    )
    
    carol_link = sign_link(carol_payload, carol_keys)
    print(f"   ✓ Carol (leaf) signed: {carol_link.payload_digest[:16]}...")
    
    # Build the chain
    chain = [alice_link, bob_link, carol_link]
    
    # Key resolver function
    key_mapping = {
        alice_keys.key_id: alice_keys.public,
        bob_keys.key_id: bob_keys.public,
        carol_keys.key_id: carol_keys.public,
    }
    
    def resolve_key(key_id: str):
        if key_id not in key_mapping:
            raise ValueError(f"Unknown key ID: {key_id}")
        return key_mapping[key_id]
    
    # Verify the chain
    print("\n3. Verifying attestation chain...")
    try:
        verify_chain(chain, resolve_key)
        print("   ✅ Chain verification successful!")
    except Exception as e:
        print(f"   ❌ Chain verification failed: {e}")
        return
    
    # Evaluate chain and get results
    print("\n4. Evaluating chain results...")
    result = evaluate_chain(chain, resolve_key)
    
    print(f"   Root Subject: {result.root_subject}")
    print(f"   Leaf Subject: {result.leaf_subject}")
    print(f"   Effective Scopes: {result.effective_scopes}")
    print(f"   Chain Depth: {result.depth}")
    print(f"   Valid Until: {time.ctime(result.latest_expiry)}")
    
    # Demonstrate revocation
    print("\n5. Testing revocation...")
    revocation_provider = InMemoryRevocationProvider()
    
    # Verify with no revocations
    options = VerificationOptions(revocation_provider=revocation_provider)
    try:
        verify_chain_with_options(chain, resolve_key, options)
        print("   ✅ Chain valid with no revocations")
    except Exception as e:
        print(f"   ❌ Unexpected verification failure: {e}")
    
    # Revoke Bob's link
    print("   🚫 Revoking Bob's delegation...")
    revocation_provider.revoke_digest(bob_link.payload_digest)
    
    try:
        verify_chain_with_options(chain, resolve_key, options)
        print("   ❌ Should have failed verification!")
    except ValueError as e:
        if "revoked link" in str(e):
            print("   ✅ Revocation correctly detected and blocked")
        else:
            print(f"   ❌ Unexpected error: {e}")
    
    # Demonstrate scope widening attack prevention
    print("\n6. Testing scope widening attack prevention...")
    
    # Try to create a malicious link that widens scopes
    malicious_payload = LinkPayload(
        parent_digest=bob_link.payload_digest,
        subject="malicious@attacker.com",
        scopes=["read", "write", "admin", "delete"],  # Trying to add more scopes
        issued_at=now,
        expires_at=now + 3600,
        audience="api.company.com",
        depth=3,
        nonce="malicious-001", 
        version=1,
    )
    
    malicious_link = sign_link(malicious_payload, carol_keys)
    malicious_chain = [alice_link, bob_link, malicious_link]
    
    try:
        verify_chain(malicious_chain, resolve_key)
        print("   ❌ Should have detected scope widening attack!")
    except ValueError as e:
        if "scope widening detected" in str(e):
            print("   ✅ Scope widening attack correctly prevented")
        else:
            print(f"   ❌ Unexpected error: {e}")
    
    # Show metrics
    print("\n7. Attestation Metrics:")
    metrics = snapshot_metrics()
    for name, value in metrics.items():
        print(f"   {name}: {value}")
    
    print("\n🎉 Attestation demo completed successfully!")


if __name__ == "__main__":
    main()