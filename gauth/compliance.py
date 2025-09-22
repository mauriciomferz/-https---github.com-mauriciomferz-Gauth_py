"""
RFC 0111 compliance check for Python implementation.

This module implements build-time exclusion checks to prevent forbidden integrations.
Forbidden: Web3/blockchain, DNA/genetic identity, AI protocol orchestration, decentralized authorization.

To use any of these, a separate license and explicit environment variable is required.
"""

import os
import sys
import warnings


def check_rfc0111_compliance():
    """
    Check RFC 0111 compliance at import time.
    
    This function prevents the use of forbidden integrations unless explicitly allowed
    through environment variables.
    """
    
    # Check for forbidden environment flags
    forbidden_flags = [
        'GAUTH_ALLOW_WEB3',
        'GAUTH_ALLOW_DNA', 
        'GAUTH_ALLOW_AI_ORCHESTRATION',
        'GAUTH_ALLOW_DECENTRALIZED_AUTH'
    ]
    
    # Check if any forbidden modules are being imported
    forbidden_modules = [
        'web3',
        'eth_account', 
        'eth_utils',
        'blockchain',
        'genetic',
        'dna_analysis',
        'bio_auth',
        'ai_orchestration',
        'decentralized_auth',
        'distributed_auth'
    ]
    
    # Get currently loaded modules
    loaded_modules = list(sys.modules.keys())
    
    # Check for forbidden imports
    violations = []
    for module_name in loaded_modules:
        for forbidden in forbidden_modules:
            if forbidden in module_name.lower():
                # Check if explicitly allowed
                allow_flag = None
                if 'web3' in forbidden or 'eth' in forbidden or 'blockchain' in forbidden:
                    allow_flag = 'GAUTH_ALLOW_WEB3'
                elif 'genetic' in forbidden or 'dna' in forbidden or 'bio' in forbidden:
                    allow_flag = 'GAUTH_ALLOW_DNA'
                elif 'ai_orchestration' in forbidden:
                    allow_flag = 'GAUTH_ALLOW_AI_ORCHESTRATION'
                elif 'decentralized' in forbidden or 'distributed_auth' in forbidden:
                    allow_flag = 'GAUTH_ALLOW_DECENTRALIZED_AUTH'
                
                if allow_flag and os.getenv(allow_flag):
                    warnings.warn(
                        f"RFC 0111 WARNING: Using forbidden module '{module_name}' "
                        f"with explicit override '{allow_flag}'. "
                        f"Ensure proper licensing compliance.",
                        RuntimeWarning
                    )
                else:
                    violations.append(module_name)
    
    if violations:
        error_msg = (
            f"RFC 0111 COMPLIANCE ERROR: Forbidden modules detected: {violations}\n"
            f"These integrations require separate licensing:\n"
            f"- Web3/blockchain integrations: Set GAUTH_ALLOW_WEB3=1\n"
            f"- DNA/genetic identity: Set GAUTH_ALLOW_DNA=1\n" 
            f"- AI orchestration: Set GAUTH_ALLOW_AI_ORCHESTRATION=1\n"
            f"- Decentralized auth: Set GAUTH_ALLOW_DECENTRALIZED_AUTH=1\n"
            f"Contact your legal team before proceeding."
        )
        raise ImportError(error_msg)


# Run compliance check when module is imported
check_rfc0111_compliance()


# Example of how to use the allowed overrides:
"""
To explicitly allow forbidden integrations, set environment variables before importing:

import os
os.environ['GAUTH_ALLOW_WEB3'] = '1'  # Only if you have proper Web3 licensing
import web3  # This would normally be forbidden

import gauth  # Will show warning but not fail
"""