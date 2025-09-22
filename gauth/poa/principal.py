"""
Principal management for Power-of-Attorney (PoA) functionality.
Implements principal verification and identity management for RFC 115 compliance.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import logging
import hashlib
import re

from .types import Principal


logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of principal verification."""
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class IdentityDocumentType(Enum):
    """Types of identity documents."""
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    NATIONAL_ID = "national_id"
    BIRTH_CERTIFICATE = "birth_certificate"
    SSN_CARD = "ssn_card"
    CORPORATE_REGISTRATION = "corporate_registration"
    ARTICLES_OF_INCORPORATION = "articles_of_incorporation"
    PARTNERSHIP_AGREEMENT = "partnership_agreement"


@dataclass
class IdentityDocument:
    """Represents an identity document."""
    type: IdentityDocumentType
    document_id: str
    issuing_authority: str
    issue_date: datetime
    expiration_date: Optional[datetime] = None
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verification_date: Optional[datetime] = None
    verification_notes: str = ""
    document_hash: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if the document has expired."""
        if not self.expiration_date:
            return False
        return datetime.now() > self.expiration_date
    
    def is_verified(self) -> bool:
        """Check if the document is verified."""
        return self.verification_status == VerificationStatus.VERIFIED


@dataclass
class IdentityVerification:
    """Complete identity verification for a principal."""
    principal_id: str
    verification_id: str
    verification_method: str  # manual, automated, third_party
    documents: List[IdentityDocument] = field(default_factory=list)
    verification_date: Optional[datetime] = None
    verified_by: str = ""
    verification_notes: str = ""
    trust_score: float = 0.0
    risk_assessment: str = "unknown"
    compliance_checks: Dict[str, bool] = field(default_factory=dict)
    
    def overall_status(self) -> VerificationStatus:
        """Get the overall verification status."""
        if not self.documents:
            return VerificationStatus.UNVERIFIED
        
        verified_docs = [doc for doc in self.documents if doc.is_verified()]
        if not verified_docs:
            return VerificationStatus.UNVERIFIED
        
        # Check if any required documents are missing or expired
        expired_docs = [doc for doc in self.documents if doc.is_expired()]
        if expired_docs:
            return VerificationStatus.EXPIRED
        
        return VerificationStatus.VERIFIED


@dataclass
class PrincipalVerification:
    """Verification record for a principal."""
    principal_id: str
    identity_verification: IdentityVerification
    background_check: Optional[Dict[str, Any]] = None
    financial_verification: Optional[Dict[str, Any]] = None
    legal_standing: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if the verification is valid."""
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        
        return self.identity_verification.overall_status() == VerificationStatus.VERIFIED


class PrincipalManager:
    """
    Manages principals and their verification status.
    """
    
    def __init__(self):
        self._principals: Dict[str, Principal] = {}
        self._verifications: Dict[str, PrincipalVerification] = {}

    async def register_principal(self, principal: Principal) -> None:
        """Register a new principal."""
        self._principals[principal.id] = principal
        logger.info(f"Registered principal {principal.id}: {principal.name}")

    async def get_principal(self, principal_id: str) -> Optional[Principal]:
        """Get a principal by ID."""
        return self._principals.get(principal_id)

    async def update_principal(self, principal: Principal) -> None:
        """Update principal information."""
        if principal.id not in self._principals:
            raise ValueError(f"Principal {principal.id} not found")
        
        self._principals[principal.id] = principal
        logger.info(f"Updated principal {principal.id}")

    async def delete_principal(self, principal_id: str) -> bool:
        """Delete a principal."""
        if principal_id not in self._principals:
            return False
        
        del self._principals[principal_id]
        
        # Also remove verification if exists
        if principal_id in self._verifications:
            del self._verifications[principal_id]
        
        logger.info(f"Deleted principal {principal_id}")
        return True

    async def initiate_verification(
        self,
        principal_id: str,
        verification_method: str = "manual"
    ) -> str:
        """Initiate identity verification for a principal."""
        if principal_id not in self._principals:
            raise ValueError(f"Principal {principal_id} not found")
        
        verification_id = f"verify_{principal_id}_{int(datetime.now().timestamp())}"
        
        identity_verification = IdentityVerification(
            principal_id=principal_id,
            verification_id=verification_id,
            verification_method=verification_method
        )
        
        verification = PrincipalVerification(
            principal_id=principal_id,
            identity_verification=identity_verification,
            expires_at=datetime.now() + timedelta(days=365)  # 1 year validity
        )
        
        self._verifications[principal_id] = verification
        
        logger.info(f"Initiated verification {verification_id} for principal {principal_id}")
        return verification_id

    async def add_identity_document(
        self,
        principal_id: str,
        document_type: IdentityDocumentType,
        document_id: str,
        issuing_authority: str,
        issue_date: datetime,
        expiration_date: Optional[datetime] = None,
        document_content: Optional[bytes] = None
    ) -> None:
        """Add an identity document to a principal's verification."""
        if principal_id not in self._verifications:
            raise ValueError(f"No verification process found for principal {principal_id}")
        
        # Calculate document hash if content provided
        document_hash = None
        if document_content:
            document_hash = hashlib.sha256(document_content).hexdigest()
        
        document = IdentityDocument(
            type=document_type,
            document_id=document_id,
            issuing_authority=issuing_authority,
            issue_date=issue_date,
            expiration_date=expiration_date,
            document_hash=document_hash
        )
        
        verification = self._verifications[principal_id]
        verification.identity_verification.documents.append(document)
        verification.updated_at = datetime.now()
        
        logger.info(f"Added {document_type.value} document for principal {principal_id}")

    async def verify_document(
        self,
        principal_id: str,
        document_id: str,
        verified_by: str,
        verification_notes: str = ""
    ) -> bool:
        """Mark a document as verified."""
        if principal_id not in self._verifications:
            return False
        
        verification = self._verifications[principal_id]
        
        for document in verification.identity_verification.documents:
            if document.document_id == document_id:
                document.verification_status = VerificationStatus.VERIFIED
                document.verification_date = datetime.now()
                document.verification_notes = verification_notes
                
                verification.identity_verification.verified_by = verified_by
                verification.identity_verification.verification_date = datetime.now()
                verification.updated_at = datetime.now()
                
                logger.info(f"Verified document {document_id} for principal {principal_id}")
                return True
        
        return False

    async def complete_verification(
        self,
        principal_id: str,
        trust_score: float,
        risk_assessment: str = "low",
        compliance_checks: Optional[Dict[str, bool]] = None
    ) -> bool:
        """Complete the verification process for a principal."""
        if principal_id not in self._verifications:
            return False
        
        verification = self._verifications[principal_id]
        
        # Check if we have at least one verified document
        verified_docs = [
            doc for doc in verification.identity_verification.documents
            if doc.is_verified()
        ]
        
        if not verified_docs:
            logger.warning(f"Cannot complete verification for {principal_id}: no verified documents")
            return False
        
        verification.identity_verification.trust_score = trust_score
        verification.identity_verification.risk_assessment = risk_assessment
        verification.identity_verification.compliance_checks = compliance_checks or {}
        verification.updated_at = datetime.now()
        
        # Update principal verification status
        principal = self._principals[principal_id]
        principal.verification_status = "verified"
        
        logger.info(f"Completed verification for principal {principal_id} with trust score {trust_score}")
        return True

    async def get_verification_status(self, principal_id: str) -> Optional[Dict[str, Any]]:
        """Get the verification status for a principal."""
        if principal_id not in self._verifications:
            return None
        
        verification = self._verifications[principal_id]
        identity_verification = verification.identity_verification
        
        return {
            'principal_id': principal_id,
            'verification_id': identity_verification.verification_id,
            'overall_status': identity_verification.overall_status().value,
            'verification_method': identity_verification.verification_method,
            'trust_score': identity_verification.trust_score,
            'risk_assessment': identity_verification.risk_assessment,
            'documents': [
                {
                    'type': doc.type.value,
                    'document_id': doc.document_id,
                    'issuing_authority': doc.issuing_authority,
                    'verification_status': doc.verification_status.value,
                    'is_expired': doc.is_expired(),
                    'verification_date': doc.verification_date.isoformat() if doc.verification_date else None
                }
                for doc in identity_verification.documents
            ],
            'compliance_checks': identity_verification.compliance_checks,
            'created_at': verification.created_at.isoformat(),
            'updated_at': verification.updated_at.isoformat(),
            'expires_at': verification.expires_at.isoformat() if verification.expires_at else None,
            'is_valid': verification.is_valid()
        }

    async def list_principals(
        self,
        verification_status: Optional[str] = None,
        principal_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List principals with optional filtering."""
        principals = []
        
        for principal in self._principals.values():
            if verification_status and principal.verification_status != verification_status:
                continue
            
            if principal_type and principal.type != principal_type:
                continue
            
            verification_info = await self.get_verification_status(principal.id)
            
            principal_info = {
                'id': principal.id,
                'name': principal.name,
                'type': principal.type,
                'legal_jurisdiction': principal.legal_jurisdiction,
                'verification_status': principal.verification_status,
                'verification_details': verification_info
            }
            
            principals.append(principal_info)
        
        return principals

    async def cleanup_expired_verifications(self) -> int:
        """Remove expired verifications."""
        expired_count = 0
        expired_principals = []
        
        for principal_id, verification in self._verifications.items():
            if verification.expires_at and datetime.now() > verification.expires_at:
                expired_principals.append(principal_id)
                expired_count += 1
                
                # Update principal status
                if principal_id in self._principals:
                    self._principals[principal_id].verification_status = "expired"
        
        # Remove expired verifications
        for principal_id in expired_principals:
            del self._verifications[principal_id]
        
        logger.info(f"Cleaned up {expired_count} expired verifications")
        return expired_count

    async def validate_principal_eligibility(
        self,
        principal_id: str,
        requirements: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Validate if a principal meets eligibility requirements."""
        principal = self._principals.get(principal_id)
        if not principal:
            return {
                'eligible': False,
                'reason': 'Principal not found',
                'requirements_met': []
            }
        
        verification = self._verifications.get(principal_id)
        if not verification or not verification.is_valid():
            return {
                'eligible': False,
                'reason': 'Principal not verified or verification expired',
                'requirements_met': []
            }
        
        requirements_met = []
        requirements_failed = []
        
        # Check basic verification
        if verification.identity_verification.overall_status() == VerificationStatus.VERIFIED:
            requirements_met.append('identity_verified')
        else:
            requirements_failed.append('identity_verification_required')
        
        # Check additional requirements if provided
        if requirements:
            if requirements.get('minimum_trust_score'):
                min_score = requirements['minimum_trust_score']
                if verification.identity_verification.trust_score >= min_score:
                    requirements_met.append('trust_score_sufficient')
                else:
                    requirements_failed.append(f'trust_score_minimum_{min_score}')
            
            if requirements.get('required_document_types'):
                required_types = set(requirements['required_document_types'])
                provided_types = {
                    doc.type.value for doc in verification.identity_verification.documents
                    if doc.is_verified()
                }
                
                if required_types.issubset(provided_types):
                    requirements_met.append('required_documents_provided')
                else:
                    missing = required_types - provided_types
                    requirements_failed.append(f'missing_documents_{list(missing)}')
        
        eligible = len(requirements_failed) == 0
        
        return {
            'eligible': eligible,
            'reason': 'All requirements met' if eligible else f"Failed: {', '.join(requirements_failed)}",
            'requirements_met': requirements_met,
            'requirements_failed': requirements_failed,
            'trust_score': verification.identity_verification.trust_score,
            'verification_status': verification.identity_verification.overall_status().value
        }