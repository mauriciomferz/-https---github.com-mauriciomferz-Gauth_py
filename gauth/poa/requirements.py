"""
RFC 115 Power-of-Attorney Requirements Module

This module defines validation requirements, constraints, and compliance
specifications for Power-of-Attorney credentials as per RFC 115.

Copyright (c) 2025 Gimel Foundation and contributors. All rights reserved.
Licensed under Apache 2.0. See LICENSE for details.
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import re

from .errors import PoAValidationError, PoAError


class ComplianceStandard(Enum):
    """Standard compliance frameworks."""
    GDPR = "gdpr"
    EIDAS_2_0 = "eidas_2.0"
    SOX = "sox"
    ISIC = "isic"
    NACE = "nace"
    ISO_27001 = "iso_27001"


class PowerLimitType(Enum):
    """Types of power limits that can be applied."""
    FINANCIAL = "financial"
    TRANSACTION_COUNT = "transaction_count"
    TIME_BASED = "time_based"
    RESOURCE_ACCESS = "resource_access"
    GEOGRAPHIC = "geographic"
    SECTOR_SPECIFIC = "sector_specific"


@dataclass
class ValidityPeriod:
    """Defines the validity period for a PoA."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    max_duration_hours: Optional[int] = None
    renewable: bool = False
    auto_renewal: bool = False
    
    def validate(self) -> bool:
        """Validate the validity period configuration."""
        if self.start_date and self.end_date:
            if self.start_date >= self.end_date:
                raise PoAValidationError("Start date must be before end date")
        
        if self.max_duration_hours and self.max_duration_hours <= 0:
            raise PoAValidationError("Max duration must be positive")
        
        return True
    
    def is_valid_at(self, check_time: datetime) -> bool:
        """Check if the PoA is valid at a specific time."""
        if self.start_date and check_time < self.start_date:
            return False
        
        if self.end_date and check_time > self.end_date:
            return False
        
        return True
    
    def is_expired(self) -> bool:
        """Check if the validity period has expired."""
        if self.end_date:
            return datetime.now() > self.end_date
        return False


@dataclass
class PowerLimits:
    """Defines quantitative limits on PoA authority."""
    financial_limit: Optional[float] = None
    transaction_count_limit: Optional[int] = None
    daily_transaction_limit: Optional[int] = None
    monthly_financial_limit: Optional[float] = None
    resource_access_limits: Dict[str, int] = field(default_factory=dict)
    geographic_restrictions: List[str] = field(default_factory=list)
    sector_restrictions: List[str] = field(default_factory=list)
    time_window_restrictions: Dict[str, str] = field(default_factory=dict)  # e.g., {"business_hours": "09:00-17:00"}
    
    def validate(self) -> bool:
        """Validate power limits configuration."""
        if self.financial_limit is not None and self.financial_limit < 0:
            raise PoAValidationError("Financial limit cannot be negative")
        
        if self.transaction_count_limit is not None and self.transaction_count_limit < 0:
            raise PoAValidationError("Transaction count limit cannot be negative")
        
        if self.daily_transaction_limit is not None and self.daily_transaction_limit < 0:
            raise PoAValidationError("Daily transaction limit cannot be negative")
        
        if self.monthly_financial_limit is not None and self.monthly_financial_limit < 0:
            raise PoAValidationError("Monthly financial limit cannot be negative")
        
        # Validate time window format
        for window, time_range in self.time_window_restrictions.items():
            if not re.match(r'^(\d{2}:\d{2})-(\d{2}:\d{2})$', time_range):
                raise PoAValidationError(f"Invalid time range format for {window}: {time_range}")
        
        return True


@dataclass
class FormalRequirements:
    """Formal requirements for PoA creation and validation."""
    notarial_certification: bool = False
    official_certification: bool = False
    resource_owner_id_verification: bool = False
    written_form_required: bool = False
    witness_required: bool = False
    digital_signature_required: bool = True
    multi_factor_authentication: bool = False
    biometric_verification: bool = False
    
    def validate(self) -> bool:
        """Validate formal requirements configuration."""
        # At least one formal requirement should be specified
        has_requirement = (
            self.notarial_certification or
            self.official_certification or
            self.resource_owner_id_verification or
            self.written_form_required or
            self.witness_required or
            self.digital_signature_required or
            self.multi_factor_authentication or
            self.biometric_verification
        )
        
        if not has_requirement:
            raise PoAValidationError("At least one formal requirement must be specified")
        
        return True


@dataclass
class ComplianceInformation:
    """Compliance and regulatory information."""
    standard: ComplianceStandard
    certification_number: Optional[str] = None
    issuing_authority: Optional[str] = None
    valid_until: Optional[datetime] = None
    compliance_level: Optional[str] = None
    audit_trail_required: bool = True
    
    def validate(self) -> bool:
        """Validate compliance information."""
        if self.valid_until and self.valid_until <= datetime.now():
            raise PoAValidationError(f"Compliance certification has expired: {self.standard.value}")
        
        if self.certification_number and len(self.certification_number.strip()) == 0:
            raise PoAValidationError("Certification number cannot be empty")
        
        return True


@dataclass
class SecurityAndCompliance:
    """Security and compliance requirements."""
    quantum_resistant: bool = False
    encryption_required: bool = True
    audit_logging_required: bool = True
    compliance_information: List[ComplianceInformation] = field(default_factory=list)
    security_clearance_level: Optional[str] = None
    data_classification_level: Optional[str] = None
    
    def validate(self) -> bool:
        """Validate security and compliance configuration."""
        for compliance in self.compliance_information:
            compliance.validate()
        
        # Validate security clearance level
        valid_clearance_levels = ["public", "internal", "confidential", "restricted", "top_secret"]
        if self.security_clearance_level and self.security_clearance_level not in valid_clearance_levels:
            raise PoAValidationError(f"Invalid security clearance level: {self.security_clearance_level}")
        
        # Validate data classification level
        valid_classification_levels = ["public", "internal", "confidential", "restricted"]
        if self.data_classification_level and self.data_classification_level not in valid_classification_levels:
            raise PoAValidationError(f"Invalid data classification level: {self.data_classification_level}")
        
        return True


@dataclass
class JurisdictionAndLaw:
    """Legal jurisdiction and applicable law."""
    applicable_law: str
    jurisdiction: str
    dispute_resolution_mechanism: Optional[str] = None
    governing_court: Optional[str] = None
    alternative_dispute_resolution: bool = False
    cross_border_recognition: bool = False
    
    def validate(self) -> bool:
        """Validate jurisdiction and law configuration."""
        if not self.applicable_law or not self.applicable_law.strip():
            raise PoAValidationError("Applicable law must be specified")
        
        if not self.jurisdiction or not self.jurisdiction.strip():
            raise PoAValidationError("Jurisdiction must be specified")
        
        return True


@dataclass
class Requirements:
    """
    Complete requirements specification for a Power-of-Attorney as per RFC 115.
    This includes validity periods, power limits, formal requirements,
    compliance information, and legal jurisdiction.
    """
    validity_period: ValidityPeriod = field(default_factory=ValidityPeriod)
    power_limits: PowerLimits = field(default_factory=PowerLimits)
    formal_requirements: FormalRequirements = field(default_factory=FormalRequirements)
    security_and_compliance: SecurityAndCompliance = field(default_factory=SecurityAndCompliance)
    jurisdiction_and_law: JurisdictionAndLaw = field(default_factory=lambda: JurisdictionAndLaw(
        applicable_law="International Commercial Law",
        jurisdiction="Universal"
    ))
    
    # RFC 115 specific exclusions
    exclude_web3: bool = True
    exclude_ai_authorization: bool = True
    exclude_dna_identity: bool = True
    gauth_context_only: bool = True
    
    def validate(self) -> bool:
        """
        Perform comprehensive validation of all requirements.
        
        Returns:
            True if all requirements are valid
            
        Raises:
            PoAValidationError: If any requirement is invalid
        """
        # Validate individual components
        self.validity_period.validate()
        self.power_limits.validate()
        self.formal_requirements.validate()
        self.security_and_compliance.validate()
        self.jurisdiction_and_law.validate()
        
        # Validate RFC 115 exclusions
        self._validate_rfc115_exclusions()
        
        return True
    
    def _validate_rfc115_exclusions(self) -> None:
        """Validate RFC 115 exclusions are properly enforced."""
        if not self.exclude_web3:
            raise PoAValidationError("RFC 115 requires exclusion of Web3/blockchain technology")
        
        if not self.exclude_ai_authorization:
            raise PoAValidationError("RFC 115 requires exclusion of AI-controlled authorization")
        
        if not self.exclude_dna_identity:
            raise PoAValidationError("RFC 115 requires exclusion of DNA-based identity systems")
        
        if not self.gauth_context_only:
            raise PoAValidationError("RFC 115 requires usage only within GAuth protocol context")
    
    def is_compliant_with(self, standard: ComplianceStandard) -> bool:
        """Check if requirements are compliant with a specific standard."""
        for compliance in self.security_and_compliance.compliance_information:
            if compliance.standard == standard:
                return compliance.validate()
        return False
    
    def get_effective_power_limits(self) -> Dict[str, Any]:
        """Get effective power limits as a dictionary."""
        limits = {}
        
        if self.power_limits.financial_limit is not None:
            limits['financial'] = self.power_limits.financial_limit
        
        if self.power_limits.transaction_count_limit is not None:
            limits['transactions'] = self.power_limits.transaction_count_limit
        
        if self.power_limits.daily_transaction_limit is not None:
            limits['daily_transactions'] = self.power_limits.daily_transaction_limit
        
        if self.power_limits.monthly_financial_limit is not None:
            limits['monthly_financial'] = self.power_limits.monthly_financial_limit
        
        return limits
    
    def check_geographic_authorization(self, region: str) -> bool:
        """Check if a geographic region is authorized."""
        if not self.power_limits.geographic_restrictions:
            return True  # No restrictions means global authorization
        
        return region in self.power_limits.geographic_restrictions
    
    def check_sector_authorization(self, sector: str) -> bool:
        """Check if an industry sector is authorized."""
        if not self.power_limits.sector_restrictions:
            return True  # No restrictions means all sectors
        
        return sector in self.power_limits.sector_restrictions
    
    def check_time_window_authorization(self, current_time: datetime) -> bool:
        """Check if current time falls within authorized time windows."""
        if not self.power_limits.time_window_restrictions:
            return True  # No restrictions means 24/7 authorization
        
        current_time_str = current_time.strftime("%H:%M")
        
        for window_name, time_range in self.power_limits.time_window_restrictions.items():
            start_time, end_time = time_range.split('-')
            if start_time <= current_time_str <= end_time:
                return True
        
        return False


def create_default_requirements() -> Requirements:
    """Create a default Requirements instance with sensible defaults."""
    return Requirements(
        validity_period=ValidityPeriod(
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=365),
            renewable=True
        ),
        power_limits=PowerLimits(
            financial_limit=10000.0,
            transaction_count_limit=100,
            daily_transaction_limit=10
        ),
        formal_requirements=FormalRequirements(
            digital_signature_required=True,
            resource_owner_id_verification=True
        ),
        security_and_compliance=SecurityAndCompliance(
            quantum_resistant=True,
            encryption_required=True,
            audit_logging_required=True,
            security_clearance_level="internal"
        )
    )


def create_enterprise_requirements() -> Requirements:
    """Create enterprise-grade Requirements with enhanced security."""
    return Requirements(
        validity_period=ValidityPeriod(
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=90),
            renewable=True,
            auto_renewal=False
        ),
        power_limits=PowerLimits(
            financial_limit=1000000.0,
            transaction_count_limit=1000,
            daily_transaction_limit=50,
            monthly_financial_limit=5000000.0
        ),
        formal_requirements=FormalRequirements(
            digital_signature_required=True,
            multi_factor_authentication=True,
            resource_owner_id_verification=True,
            official_certification=True
        ),
        security_and_compliance=SecurityAndCompliance(
            quantum_resistant=True,
            encryption_required=True,
            audit_logging_required=True,
            security_clearance_level="confidential",
            data_classification_level="confidential",
            compliance_information=[
                ComplianceInformation(
                    standard=ComplianceStandard.GDPR,
                    compliance_level="full",
                    audit_trail_required=True
                ),
                ComplianceInformation(
                    standard=ComplianceStandard.ISO_27001,
                    compliance_level="certified",
                    audit_trail_required=True
                )
            ]
        )
    )


def create_individual_requirements() -> Requirements:
    """Create individual-focused Requirements with appropriate restrictions."""
    return Requirements(
        validity_period=ValidityPeriod(
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=30),
            renewable=True
        ),
        power_limits=PowerLimits(
            financial_limit=1000.0,
            transaction_count_limit=20,
            daily_transaction_limit=5
        ),
        formal_requirements=FormalRequirements(
            digital_signature_required=True,
            resource_owner_id_verification=True
        ),
        security_and_compliance=SecurityAndCompliance(
            encryption_required=True,
            audit_logging_required=True,
            security_clearance_level="internal"
        )
    )