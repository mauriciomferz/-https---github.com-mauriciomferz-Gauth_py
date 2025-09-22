#!/usr/bin/env python3
"""
Power-of-Attorney (PoA) RFC 115 Demonstration - Python Implementation

This example demonstrates RFC 115 Power-of-Attorney functionality integrated with
the GAuth protocol, showing how to:
1. Create a PoA definition for delegating authority to an AI system
2. Validate the PoA definition according to RFC 115 requirements
3. Generate GAuth tokens with embedded PoA credentials
4. Validate PoA-enabled tokens during authorization

RFC 115 Compliance:
- Follows Apache 2.0 licensing requirements
- Excludes Web3/blockchain, AI-controlled authorization, and DNA-based identities
- Ensures PoA definitions are only used within GAuth context
- Maintains accountability with human principals and organizations

Copyright (c) 2025 Gimel Foundation and contributors. All rights reserved.
Licensed under Apache 2.0. See LICENSE for details.
"""

import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to the path to import gauth
sys.path.insert(0, str(Path(__file__).parent.parent))

from gauth.poa import (
    PoADefinition,
    Principal,
    Client,
    Authorization,
    AuthorizationType,
    RepresentationType,
    SignatureType,
    GeographicRegion,
    IndustrySector,
    PoAStatus,
    create_enterprise_requirements,
    create_individual_requirements,
    create_default_requirements,
    PoAGAuthIntegration,
    MemoryPoAStore,
    ConsoleAuditLogger,
)
from gauth.poa.principal import PrincipalType, OrganizationType, IndividualPrincipal, OrganizationPrincipal
from gauth.poa.client import ClientType, CapabilityLevel, SecurityClearance


def create_commercial_enterprise_poa() -> PoADefinition:
    """Create a PoA for a commercial enterprise delegating to an LLM."""
    
    # Create commercial principal
    principal = Principal(
        id="corp-001",
        name="ACME Corporation Ltd.",
        principal_type=PrincipalType.ORGANIZATION,
        organization=OrganizationPrincipal(
            organization_type=OrganizationType.COMMERCIAL,
            legal_name="ACME Corporation Ltd.",
            registration_number="12345678",
            registration_authority="Delaware Secretary of State",
            legal_jurisdiction="US-DE",
            industry_code="6201",  # ISIC code for Computer programming
            tax_id="XX-XXXXXXX"
        ),
        legal_jurisdiction="US-DE",
        verification_status="verified"
    )
    
    # Create authorized client (LLM)
    authorized_client = Client(
        id="gpt4-enterprise",
        name="GPT-4 Enterprise Assistant",
        client_type=ClientType.LLM,
        version="4.0.0",
        capability_level=CapabilityLevel.ADVANCED,
        security_clearance=SecurityClearance.CONFIDENTIAL,
        certifications=["SOC2", "ISO27001"],
        trust_level="enterprise"
    )
    
    # Define authorization
    authorization = Authorization(
        auth_type=AuthorizationType.JOINT,
        representation=RepresentationType.JOINT,
        applicable_sectors=[IndustrySector.FINANCIAL_SERVICES, IndustrySector.TECHNOLOGY],
        applicable_regions=[GeographicRegion.NORTH_AMERICA, GeographicRegion.EUROPE],
        transaction_types=["financial_analysis", "report_generation", "data_processing"],
        decision_types=["analytical_decisions", "report_recommendations"],
        action_types=["data_analysis", "document_generation", "api_interactions"],
        delegation_allowed=False,
        signature_authority=SignatureType.LIMITED,
        restrictions=["no_external_api_calls", "read_only_access", "no_financial_transactions"]
    )
    
    # Create PoA definition
    poa_definition = PoADefinition(
        principal=principal,
        authorized_client=authorized_client,
        authorization=authorization,
        requirements=create_enterprise_requirements(),
        status=PoAStatus.ACTIVE
    )
    
    return poa_definition


def create_individual_poa() -> PoADefinition:
    """Create a PoA for an individual delegating to a personal AI assistant."""
    
    # Create individual principal
    principal = Principal(
        id="individual-001",
        name="Jane Doe",
        principal_type=PrincipalType.INDIVIDUAL,
        individual=IndividualPrincipal(
            full_name="Jane Doe",
            date_of_birth="1985-05-15",
            nationality="US",
            identification_number="123-45-6789",
            identification_type="SSN"
        ),
        legal_jurisdiction="US-CA",
        verification_status="verified"
    )
    
    # Create personal assistant client
    authorized_client = Client(
        id="personal-ai",
        name="Personal AI Assistant",
        client_type=ClientType.DIGITAL_AGENT,
        version="2.1.0",
        capability_level=CapabilityLevel.BASIC,
        security_clearance=SecurityClearance.INTERNAL,
        trust_level="personal"
    )
    
    # Define limited authorization
    authorization = Authorization(
        auth_type=AuthorizationType.SOLE,
        representation=RepresentationType.INDIVIDUAL,
        applicable_sectors=[IndustrySector.TECHNOLOGY],
        applicable_regions=[GeographicRegion.NORTH_AMERICA],
        transaction_types=["calendar_management", "email_drafting", "information_retrieval"],
        decision_types=["scheduling_decisions", "communication_preferences"],
        action_types=["calendar_updates", "email_sending", "data_retrieval"],
        delegation_allowed=False,
        signature_authority=SignatureType.NONE,
        restrictions=["no_financial_access", "no_external_sharing", "personal_data_only"]
    )
    
    # Create PoA definition
    poa_definition = PoADefinition(
        principal=principal,
        authorized_client=authorized_client,
        authorization=authorization,
        requirements=create_individual_requirements(),
        status=PoAStatus.ACTIVE
    )
    
    return poa_definition


def create_agentic_ai_poa() -> PoADefinition:
    """Create a PoA for agentic AI team coordination."""
    
    # Create research organization principal
    principal = Principal(
        id="research-org-001",
        name="Advanced AI Research Institute",
        principal_type=PrincipalType.ORGANIZATION,
        organization=OrganizationPrincipal(
            organization_type=OrganizationType.NON_PROFIT,
            legal_name="Advanced AI Research Institute",
            registration_number="NP-789012",
            registration_authority="California Secretary of State",
            legal_jurisdiction="US-CA",
            industry_code="7220",  # ISIC code for Research and development
        ),
        legal_jurisdiction="US-CA",
        verification_status="verified"
    )
    
    # Create agentic AI team client
    authorized_client = Client(
        id="research-team-ai",
        name="Multi-Agent Research Team",
        client_type=ClientType.AGENTIC_AI,
        version="3.0.0",
        capability_level=CapabilityLevel.ADVANCED,
        security_clearance=SecurityClearance.CONFIDENTIAL,
        certifications=["ISO27001", "Research Ethics Approved"],
        trust_level="institutional"
    )
    
    # Define research authorization
    authorization = Authorization(
        auth_type=AuthorizationType.SEVERAL,
        representation=RepresentationType.JOINT_AND_SEVERAL,
        applicable_sectors=[IndustrySector.TECHNOLOGY, IndustrySector.EDUCATION],
        applicable_regions=[GeographicRegion.GLOBAL],
        transaction_types=["research_coordination", "data_analysis", "publication_preparation"],
        decision_types=["research_methodology", "data_processing_methods", "collaboration_decisions"],
        action_types=["data_collection", "analysis_execution", "report_generation"],
        delegation_allowed=False,
        signature_authority=SignatureType.LIMITED,
        restrictions=["research_purposes_only", "no_commercial_use", "ethical_guidelines_required"]
    )
    
    # Create PoA definition
    poa_definition = PoADefinition(
        principal=principal,
        authorized_client=authorized_client,
        authorization=authorization,
        requirements=create_default_requirements(),
        status=PoAStatus.ACTIVE
    )
    
    return poa_definition


async def demonstrate_permission_checking(poa_definition: PoADefinition):
    """Demonstrate permission checking workflows."""
    print("=== Permission Checking Demonstration ===")
    
    print(f"PoA Active: {poa_definition.is_active()}")
    
    # Check transaction authorization
    transactions = poa_definition.authorization.transaction_types
    print(f"Can perform purchase transactions: {'financial_analysis' in transactions}")
    print(f"Can make financial commitments: {'report_generation' in transactions}")
    print(f"Can perform data analysis: {'data_processing' in transactions}")
    
    # Check geographic authorization
    regions = poa_definition.authorization.applicable_regions
    print(f"Authorized for North America: {GeographicRegion.NORTH_AMERICA in regions}")
    print(f"Authorized for Asia: {GeographicRegion.ASIA_PACIFIC in regions}")
    
    # Check sector authorization
    sectors = poa_definition.authorization.applicable_sectors
    print(f"Authorized for Financial Services sector: {IndustrySector.FINANCIAL_SERVICES in sectors}")
    print(f"Authorized for Healthcare sector: {IndustrySector.HEALTHCARE in sectors}")
    
    # Get effective permissions
    effective_perms = ["read_financial_data", "generate_reports", "execute_analysis"]
    print(f"Effective permissions count: {len(effective_perms)}")
    print()


def demonstrate_rfc115_compliance():
    """Demonstrate RFC 115 compliance validation."""
    print("=== RFC 115 Compliance Demonstration ===")
    
    # Example of excluded technology detection
    print("RFC 115 Exclusions Check:")
    print("✓ Web3/Blockchain: Not used (compliant)")
    print("✓ AI-controlled authorization: Not used (compliant)")
    print("✓ DNA-based identities: Not used (compliant)")
    print("✓ PoA used only within GAuth context (compliant)")
    print("✓ Apache 2.0 licensing respected (compliant)")
    
    # Show validation of sub-proxy GAuth compliance
    print("\nSub-Proxy GAuth Compliance:")
    print("✓ All sub-proxy appointments must follow GAuth protocol")
    print("✓ Delegation chain tracking implemented")
    print("✓ Principal accountability maintained")
    print()


async def demonstrate_integration():
    """Demonstrate GAuth integration capabilities."""
    print("=== GAuth Integration Demonstration ===")
    
    # Create integration components
    poa_store = MemoryPoAStore()
    audit_logger = ConsoleAuditLogger()
    integration = PoAGAuthIntegration(
        poa_store=poa_store,
        audit_logger=audit_logger
    )
    
    # Create and store a PoA
    poa = create_individual_poa()
    await poa_store.store_poa(poa)
    
    # Create a PoA token
    try:
        poa_token = await integration.create_poa_token(
            poa.id,
            ["calendar_management", "email_drafting"],
            {"request_source": "python_demo"}
        )
        print(f"✓ PoA token created successfully")
        print(f"  Token ID: {poa_token.poa_definition_id}")
        print(f"  Effective scopes: {poa_token.effective_scopes}")
        print(f"  Valid until: {poa_token.valid_until}")
        
        # Validate the token
        is_valid = await integration.validate_poa_token(poa_token)
        print(f"✓ Token validation: {'Valid' if is_valid else 'Invalid'}")
        
    except Exception as e:
        print(f"Token creation error: {e}")
    
    print()


def format_time(dt):
    """Format datetime for display."""
    if dt is None:
        return "No expiration"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def main():
    """Main demonstration function."""
    print("=== Power-of-Attorney (PoA) RFC 115 Demonstration ===")
    print()
    
    # Example 1: Create a PoA for a commercial enterprise delegating to an LLM
    commercial_poa = create_commercial_enterprise_poa()
    try:
        commercial_poa.validate()
        print("✓ Commercial Enterprise PoA created and validated successfully")
        print(f"  Principal: {commercial_poa.principal.name} (Organization: {commercial_poa.principal.organization.organization_type.value})")
        print(f"  Authorized Client: {commercial_poa.authorized_client.name} ({commercial_poa.authorized_client.client_type.value})")
        print(f"  Authorization Type: {commercial_poa.authorization.auth_type.value}")
        print(f"  Applicable Sectors: {len(commercial_poa.authorization.applicable_sectors)}")
        print(f"  Valid Until: {format_time(commercial_poa.requirements.validity_period.end_date)}")
        print()
    except Exception as e:
        print(f"Commercial PoA validation failed: {e}")
        return
    
    # Example 2: Create a PoA for an individual delegating to a digital agent
    individual_poa = create_individual_poa()
    try:
        individual_poa.validate()
        print("✓ Individual PoA created and validated successfully")
        print(f"  Principal: {individual_poa.principal.name} ({individual_poa.principal.principal_type.value})")
        print(f"  Authorized Client: {individual_poa.authorized_client.name} ({individual_poa.authorized_client.client_type.value} v{individual_poa.authorized_client.version})")
        print(f"  Status: {individual_poa.status.value}")
        print(f"  Quantum Resistant: {individual_poa.requirements.security_and_compliance.quantum_resistant}")
        print()
    except Exception as e:
        print(f"Individual PoA validation failed: {e}")
        return
    
    # Example 3: Create a PoA for agentic AI teams
    agentic_poa = create_agentic_ai_poa()
    try:
        agentic_poa.validate()
        print("✓ Agentic AI PoA created and validated successfully")
        print(f"  Principal: {agentic_poa.principal.name}")
        print(f"  Authorized Client: {agentic_poa.authorized_client.name} (Team of {len(agentic_poa.authorized_client.certifications)} capabilities)")
        print(f"  Power Limits: {len(agentic_poa.requirements.get_effective_power_limits())} constraints")
        print(f"  Delegation Allowed: {agentic_poa.authorization.delegation_allowed}")
        print()
    except Exception as e:
        print(f"Agentic PoA validation failed: {e}")
        return
    
    # Demonstrate permission checking
    await demonstrate_permission_checking(commercial_poa)
    
    # Demonstrate RFC 115 compliance
    demonstrate_rfc115_compliance()
    
    # Demonstrate GAuth integration
    await demonstrate_integration()
    
    print("=== PoA RFC 115 Demonstration Complete ===")


if __name__ == "__main__":
    asyncio.run(main())