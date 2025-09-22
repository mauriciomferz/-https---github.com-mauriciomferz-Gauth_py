"""
Power-of-Attorney types for the GAuth protocol (GiFo-RfC 115).
Implements RFC 115 compliant PoA structures and enumerations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import uuid


class AuthorizationType(Enum):
    """Fundamental type of authorization (RFC 115 Section B)."""
    SOLE = "sole"                    # Client can act independently
    JOINT = "joint"                  # Client must act with others
    SEVERAL = "several"              # Client shares authority with others
    CONTINGENT = "contingent"        # Authorization subject to conditions
    SPECIAL = "special"              # Special limited authorization
    GENERAL = "general"              # General broad authorization


class RepresentationType(Enum):
    """Whether the client acts alone or jointly (RFC 115 Section B)."""
    INDIVIDUAL = "individual"        # Acts alone
    JOINT = "joint"                 # Must act with specified others
    JOINT_AND_SEVERAL = "joint_and_several"  # Can act alone or with others


class SignatureType(Enum):
    """Signature authorization level (RFC 115 Section B)."""
    NONE = "none"                   # No signature authority
    LIMITED = "limited"             # Limited signature authority
    FULL = "full"                   # Full signature authority
    CONDITIONAL = "conditional"      # Conditional signature authority


class GeographicRegion(Enum):
    """Geographic regions for PoA scope (RFC 115 Section B)."""
    GLOBAL = "global"
    NORTH_AMERICA = "north_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    LATIN_AMERICA = "latin_america"
    MIDDLE_EAST_AFRICA = "middle_east_africa"
    DOMESTIC = "domestic"           # Within principal's country
    INTERNATIONAL = "international"  # Outside principal's country


class IndustrySector(Enum):
    """Industry sectors for PoA scope (RFC 115 Section B)."""
    FINANCIAL_SERVICES = "financial_services"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    TELECOMMUNICATIONS = "telecommunications"
    TRANSPORTATION = "transportation"
    RETAIL = "retail"
    REAL_ESTATE = "real_estate"
    LEGAL_SERVICES = "legal_services"
    GOVERNMENT = "government"
    EDUCATION = "education"
    NON_PROFIT = "non_profit"
    ALL_SECTORS = "all_sectors"


class DelegationLevel(Enum):
    """Level of delegation authority (RFC 115 Section C)."""
    NONE = "none"                   # No delegation allowed
    LIMITED = "limited"             # Limited delegation with restrictions
    FULL = "full"                   # Full delegation authority
    CASCADE = "cascade"             # Can delegate delegation authority


class PoAStatus(Enum):
    """Status of a Power-of-Attorney document."""
    DRAFT = "draft"                 # Being prepared
    ACTIVE = "active"               # Currently valid
    SUSPENDED = "suspended"         # Temporarily inactive
    REVOKED = "revoked"            # Permanently canceled
    EXPIRED = "expired"             # Past validity period
    TERMINATED = "terminated"       # Ended by mutual agreement


@dataclass
class SubProxyRules:
    """Rules for appointing sub-proxies (RFC 115 Section C)."""
    max_delegation_depth: int = 1
    require_principal_approval: bool = True
    allowed_delegation_types: Set[AuthorizationType] = field(default_factory=set)
    prohibited_actions: List[str] = field(default_factory=list)
    delegation_period_limit: Optional[timedelta] = None
    notification_required: bool = True


@dataclass
class Requirements:
    """Requirements that must be met for PoA validity (RFC 115 Section D)."""
    minimum_age: Optional[int] = None
    required_certifications: List[str] = field(default_factory=list)
    required_licenses: List[str] = field(default_factory=list)
    background_check_required: bool = False
    financial_qualification_required: bool = False
    insurance_required: bool = False
    bonding_required: bool = False
    periodic_review_required: bool = False
    continuing_education_required: bool = False


@dataclass
class Restrictions:
    """Restrictions on PoA exercise (RFC 115 Section D)."""
    monetary_limits: Dict[str, float] = field(default_factory=dict)
    transaction_frequency_limits: Dict[str, int] = field(default_factory=dict)
    prohibited_actions: List[str] = field(default_factory=list)
    required_approvals: List[str] = field(default_factory=list)
    time_restrictions: Dict[str, Any] = field(default_factory=dict)
    geographic_restrictions: List[GeographicRegion] = field(default_factory=list)
    sector_restrictions: List[IndustrySector] = field(default_factory=list)


@dataclass
class Principal:
    """
    The party granting power-of-attorney (RFC 115 Section A).
    """
    id: str
    name: str
    type: str  # individual, corporation, partnership, etc.
    legal_jurisdiction: str
    contact_information: Dict[str, str] = field(default_factory=dict)
    verification_status: str = "unverified"
    identity_documents: List[str] = field(default_factory=list)
    authorized_representatives: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'legal_jurisdiction': self.legal_jurisdiction,
            'contact_information': self.contact_information,
            'verification_status': self.verification_status,
            'identity_documents': self.identity_documents,
            'authorized_representatives': self.authorized_representatives
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Principal':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            name=data['name'],
            type=data['type'],
            legal_jurisdiction=data['legal_jurisdiction'],
            contact_information=data.get('contact_information', {}),
            verification_status=data.get('verification_status', 'unverified'),
            identity_documents=data.get('identity_documents', []),
            authorized_representatives=data.get('authorized_representatives', [])
        )


@dataclass
class Client:
    """
    The party receiving power-of-attorney (RFC 115 Section A).
    """
    id: str
    name: str
    type: str  # individual, ai_system, service, organization, etc.
    capabilities: List[str] = field(default_factory=list)
    certifications: List[str] = field(default_factory=list)
    verification_status: str = "unverified"
    trust_level: str = "basic"
    operational_constraints: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'capabilities': self.capabilities,
            'certifications': self.certifications,
            'verification_status': self.verification_status,
            'trust_level': self.trust_level,
            'operational_constraints': self.operational_constraints
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Client':
        """Create from dictionary representation."""
        return cls(
            id=data['id'],
            name=data['name'],
            type=data['type'],
            capabilities=data.get('capabilities', []),
            certifications=data.get('certifications', []),
            verification_status=data.get('verification_status', 'unverified'),
            trust_level=data.get('trust_level', 'basic'),
            operational_constraints=data.get('operational_constraints', {})
        )


@dataclass
class Authorization:
    """
    Defines the type and scope of powers being delegated (RFC 115 Section B).
    """
    type: AuthorizationType
    representation: RepresentationType
    applicable_sectors: List[IndustrySector] = field(default_factory=list)
    applicable_regions: List[GeographicRegion] = field(default_factory=list)
    transaction_types: List[str] = field(default_factory=list)
    decision_types: List[str] = field(default_factory=list)
    action_types: List[str] = field(default_factory=list)
    delegation_allowed: bool = False
    signature_authority: SignatureType = SignatureType.NONE
    restrictions: List[str] = field(default_factory=list)
    sub_proxy_rules: Optional[SubProxyRules] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': self.type.value,
            'representation': self.representation.value,
            'applicable_sectors': [s.value for s in self.applicable_sectors],
            'applicable_regions': [r.value for r in self.applicable_regions],
            'transaction_types': self.transaction_types,
            'decision_types': self.decision_types,
            'action_types': self.action_types,
            'delegation_allowed': self.delegation_allowed,
            'signature_authority': self.signature_authority.value,
            'restrictions': self.restrictions,
            'sub_proxy_rules': self.sub_proxy_rules.__dict__ if self.sub_proxy_rules else None
        }


@dataclass
class PowerOfAttorney:
    """
    Complete Power-of-Attorney document (RFC 115).
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    effective_date: datetime = field(default_factory=datetime.now)
    expiration_date: Optional[datetime] = None
    
    # Parties
    principal: Principal = None
    client: Client = None
    
    # Authorization details
    authorization: Authorization = None
    
    # Requirements and restrictions
    requirements: Requirements = field(default_factory=Requirements)
    restrictions: Restrictions = field(default_factory=Restrictions)
    
    # Status and metadata
    status: PoAStatus = PoAStatus.DRAFT
    jurisdiction: str = ""
    governing_law: str = ""
    dispute_resolution: str = "arbitration"
    
    # Signatures and witnesses
    principal_signature: Optional[str] = None
    client_signature: Optional[str] = None
    witness_signatures: List[str] = field(default_factory=list)
    notarization: Optional[Dict[str, Any]] = None
    
    # Audit trail
    created_by: str = ""
    last_modified_by: str = ""
    last_modified_at: datetime = field(default_factory=datetime.now)
    revision_history: List[Dict[str, Any]] = field(default_factory=list)

    def is_valid(self) -> bool:
        """Check if the PoA is currently valid."""
        if self.status != PoAStatus.ACTIVE:
            return False
        
        now = datetime.now()
        
        # Check effective date
        if now < self.effective_date:
            return False
        
        # Check expiration
        if self.expiration_date and now > self.expiration_date:
            return False
        
        return True

    def is_expired(self) -> bool:
        """Check if the PoA has expired."""
        if not self.expiration_date:
            return False
        return datetime.now() > self.expiration_date

    def time_until_expiration(self) -> Optional[timedelta]:
        """Get time until expiration."""
        if not self.expiration_date:
            return None
        return self.expiration_date - datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'version': self.version,
            'created_at': self.created_at.isoformat(),
            'effective_date': self.effective_date.isoformat(),
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'principal': self.principal.to_dict() if self.principal else None,
            'client': self.client.to_dict() if self.client else None,
            'authorization': self.authorization.to_dict() if self.authorization else None,
            'requirements': self.requirements.__dict__,
            'restrictions': self.restrictions.__dict__,
            'status': self.status.value,
            'jurisdiction': self.jurisdiction,
            'governing_law': self.governing_law,
            'dispute_resolution': self.dispute_resolution,
            'principal_signature': self.principal_signature,
            'client_signature': self.client_signature,
            'witness_signatures': self.witness_signatures,
            'notarization': self.notarization,
            'created_by': self.created_by,
            'last_modified_by': self.last_modified_by,
            'last_modified_at': self.last_modified_at.isoformat(),
            'revision_history': self.revision_history
        }


@dataclass
class ValidationResult:
    """Result of PoA validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    validation_timestamp: datetime = field(default_factory=datetime.now)
    validator: str = ""
    
    def add_error(self, error: str) -> None:
        """Add a validation error."""
        self.errors.append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add a validation warning."""
        self.warnings.append(warning)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'validation_timestamp': self.validation_timestamp.isoformat(),
            'validator': self.validator
        }