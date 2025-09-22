"""
Client management for Power-of-Attorney (PoA) functionality.
Implements client registration and capabilities management for RFC 115 compliance.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import logging

from .types import Client


logger = logging.getLogger(__name__)


class ClientType(Enum):
    """Types of clients that can receive PoA."""
    INDIVIDUAL = "individual"
    AI_SYSTEM = "ai_system"
    LLM = "llm"  # Large Language Model
    DIGITAL_AGENT = "digital_agent"  # Digital agent
    AGENTIC_AI = "agentic_ai"  # Agentic AI
    SERVICE = "service"
    ORGANIZATION = "organization"
    SOFTWARE_AGENT = "software_agent"
    LEGAL_ENTITY = "legal_entity"


class TrustLevel(Enum):
    """Trust levels for clients."""
    BASIC = "basic"
    STANDARD = "standard"
    HIGH = "high"
    CRITICAL = "critical"


class CapabilityType(Enum):
    """Types of capabilities a client can have."""
    TRADING = "trading"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    DOCUMENT_PROCESSING = "document_processing"
    DECISION_MAKING = "decision_making"
    COMMUNICATION = "communication"
    DATA_ACCESS = "data_access"
    TRANSACTION_PROCESSING = "transaction_processing"
    SIGNATURE = "signature"
    DELEGATION = "delegation"


class CapabilityLevel(Enum):
    """Capability levels for clients."""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class SecurityClearance(Enum):
    """Security clearance levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


@dataclass
class ClientCapabilities:
    """Represents capabilities of a client."""
    technical_capabilities: List[CapabilityType] = field(default_factory=list)
    business_capabilities: List[str] = field(default_factory=list)
    processing_limits: Dict[str, Any] = field(default_factory=dict)
    security_features: List[str] = field(default_factory=list)
    compliance_certifications: List[str] = field(default_factory=list)
    operational_constraints: Dict[str, Any] = field(default_factory=dict)
    
    def has_capability(self, capability: CapabilityType) -> bool:
        """Check if client has a specific capability."""
        return capability in self.technical_capabilities
    
    def can_handle_business_function(self, function: str) -> bool:
        """Check if client can handle a business function."""
        return function in self.business_capabilities


@dataclass
class ClientRegistration:
    """Registration information for a client."""
    client_id: str
    registration_date: datetime
    registered_by: str
    verification_status: str = "pending"
    verification_date: Optional[datetime] = None
    verification_notes: str = ""
    compliance_status: str = "unknown"
    last_audit_date: Optional[datetime] = None
    certification_expiry: Optional[datetime] = None
    
    def is_verified(self) -> bool:
        """Check if client is verified."""
        return self.verification_status == "verified"
    
    def is_compliance_current(self) -> bool:
        """Check if compliance is current."""
        if not self.certification_expiry:
            return True
        return datetime.now() < self.certification_expiry


class ClientManager:
    """
    Manages clients and their capabilities for PoA operations.
    """
    
    def __init__(self):
        self._clients: Dict[str, Client] = {}
        self._registrations: Dict[str, ClientRegistration] = {}
        self._capabilities: Dict[str, ClientCapabilities] = {}

    async def register_client(
        self,
        client: Client,
        registered_by: str,
        capabilities: Optional[ClientCapabilities] = None
    ) -> str:
        """Register a new client."""
        self._clients[client.id] = client
        
        registration = ClientRegistration(
            client_id=client.id,
            registration_date=datetime.now(),
            registered_by=registered_by
        )
        self._registrations[client.id] = registration
        
        if capabilities:
            self._capabilities[client.id] = capabilities
        else:
            # Create default capabilities based on client type
            self._capabilities[client.id] = self._create_default_capabilities(client)
        
        logger.info(f"Registered client {client.id}: {client.name}")
        return client.id

    def _create_default_capabilities(self, client: Client) -> ClientCapabilities:
        """Create default capabilities based on client type."""
        capabilities = ClientCapabilities()
        
        if client.type == "ai_system":
            capabilities.technical_capabilities = [
                CapabilityType.ANALYSIS,
                CapabilityType.DECISION_MAKING,
                CapabilityType.DATA_ACCESS
            ]
            capabilities.security_features = ["encryption", "audit_logging"]
        elif client.type == "service":
            capabilities.technical_capabilities = [
                CapabilityType.TRANSACTION_PROCESSING,
                CapabilityType.COMMUNICATION
            ]
            capabilities.security_features = ["authentication", "authorization"]
        elif client.type == "individual":
            capabilities.technical_capabilities = [
                CapabilityType.DECISION_MAKING,
                CapabilityType.SIGNATURE
            ]
        
        return capabilities

    async def get_client(self, client_id: str) -> Optional[Client]:
        """Get a client by ID."""
        return self._clients.get(client_id)

    async def update_client(self, client: Client) -> None:
        """Update client information."""
        if client.id not in self._clients:
            raise ValueError(f"Client {client.id} not found")
        
        self._clients[client.id] = client
        logger.info(f"Updated client {client.id}")

    async def verify_client(
        self,
        client_id: str,
        verified_by: str,
        verification_notes: str = ""
    ) -> bool:
        """Verify a client."""
        if client_id not in self._registrations:
            return False
        
        registration = self._registrations[client_id]
        registration.verification_status = "verified"
        registration.verification_date = datetime.now()
        registration.verification_notes = verification_notes
        
        # Update client verification status
        if client_id in self._clients:
            self._clients[client_id].verification_status = "verified"
        
        logger.info(f"Verified client {client_id} by {verified_by}")
        return True

    async def update_capabilities(
        self,
        client_id: str,
        capabilities: ClientCapabilities
    ) -> None:
        """Update client capabilities."""
        if client_id not in self._clients:
            raise ValueError(f"Client {client_id} not found")
        
        self._capabilities[client_id] = capabilities
        logger.info(f"Updated capabilities for client {client_id}")

    async def get_capabilities(self, client_id: str) -> Optional[ClientCapabilities]:
        """Get client capabilities."""
        return self._capabilities.get(client_id)

    async def check_capability_authorization(
        self,
        client_id: str,
        required_capability: CapabilityType,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if client is authorized for a capability."""
        client = self._clients.get(client_id)
        if not client:
            return False
        
        # Check if client is verified
        registration = self._registrations.get(client_id)
        if not registration or not registration.is_verified():
            return False
        
        # Check capabilities
        capabilities = self._capabilities.get(client_id)
        if not capabilities:
            return False
        
        if not capabilities.has_capability(required_capability):
            return False
        
        # Check operational constraints
        if context and capabilities.operational_constraints:
            for constraint, value in capabilities.operational_constraints.items():
                if constraint in context and context[constraint] != value:
                    return False
        
        return True

    async def get_client_status(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive client status."""
        client = self._clients.get(client_id)
        if not client:
            return None
        
        registration = self._registrations.get(client_id)
        capabilities = self._capabilities.get(client_id)
        
        return {
            'client_id': client_id,
            'name': client.name,
            'type': client.type,
            'verification_status': client.verification_status,
            'trust_level': client.trust_level,
            'registration': {
                'registration_date': registration.registration_date.isoformat() if registration else None,
                'verified': registration.is_verified() if registration else False,
                'verification_date': registration.verification_date.isoformat() if registration and registration.verification_date else None,
                'compliance_current': registration.is_compliance_current() if registration else False
            } if registration else None,
            'capabilities': {
                'technical': [cap.value for cap in capabilities.technical_capabilities] if capabilities else [],
                'business': capabilities.business_capabilities if capabilities else [],
                'security_features': capabilities.security_features if capabilities else [],
                'certifications': capabilities.compliance_certifications if capabilities else []
            } if capabilities else None
        }

    async def list_clients(
        self,
        client_type: Optional[str] = None,
        verification_status: Optional[str] = None,
        trust_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List clients with optional filtering."""
        clients = []
        
        for client in self._clients.values():
            if client_type and client.type != client_type:
                continue
            
            if verification_status and client.verification_status != verification_status:
                continue
            
            if trust_level and client.trust_level != trust_level:
                continue
            
            client_status = await self.get_client_status(client.id)
            if client_status:
                clients.append(client_status)
        
        return clients

    async def find_capable_clients(
        self,
        required_capabilities: List[CapabilityType],
        business_functions: Optional[List[str]] = None,
        min_trust_level: Optional[TrustLevel] = None
    ) -> List[Dict[str, Any]]:
        """Find clients with specific capabilities."""
        capable_clients = []
        
        trust_levels = {
            TrustLevel.BASIC: 1,
            TrustLevel.STANDARD: 2,
            TrustLevel.HIGH: 3,
            TrustLevel.CRITICAL: 4
        }
        
        min_trust_value = trust_levels.get(min_trust_level, 0) if min_trust_level else 0
        
        for client_id, client in self._clients.items():
            # Check trust level
            if min_trust_level:
                client_trust_value = trust_levels.get(TrustLevel(client.trust_level), 0)
                if client_trust_value < min_trust_value:
                    continue
            
            # Check verification
            registration = self._registrations.get(client_id)
            if not registration or not registration.is_verified():
                continue
            
            # Check capabilities
            capabilities = self._capabilities.get(client_id)
            if not capabilities:
                continue
            
            # Check technical capabilities
            has_all_capabilities = all(
                capabilities.has_capability(cap) for cap in required_capabilities
            )
            
            if not has_all_capabilities:
                continue
            
            # Check business functions if specified
            if business_functions:
                has_business_functions = all(
                    capabilities.can_handle_business_function(func) for func in business_functions
                )
                if not has_business_functions:
                    continue
            
            client_status = await self.get_client_status(client_id)
            if client_status:
                capable_clients.append(client_status)
        
        return capable_clients

    async def update_trust_level(
        self,
        client_id: str,
        new_trust_level: TrustLevel,
        updated_by: str,
        reason: str = ""
    ) -> bool:
        """Update client trust level."""
        client = self._clients.get(client_id)
        if not client:
            return False
        
        old_trust_level = client.trust_level
        client.trust_level = new_trust_level.value
        
        logger.info(
            f"Updated trust level for client {client_id} from {old_trust_level} to {new_trust_level.value} "
            f"by {updated_by}: {reason}"
        )
        return True

    async def suspend_client(
        self,
        client_id: str,
        suspended_by: str,
        reason: str = ""
    ) -> bool:
        """Suspend a client."""
        if client_id not in self._clients:
            return False
        
        registration = self._registrations.get(client_id)
        if registration:
            registration.verification_status = "suspended"
            registration.verification_notes = f"Suspended by {suspended_by}: {reason}"
        
        logger.info(f"Suspended client {client_id} by {suspended_by}: {reason}")
        return True

    async def cleanup_expired_registrations(self) -> int:
        """Clean up expired client registrations."""
        expired_count = 0
        expired_clients = []
        
        for client_id, registration in self._registrations.items():
            if not registration.is_compliance_current():
                expired_clients.append(client_id)
                expired_count += 1
                
                # Update client status
                if client_id in self._clients:
                    self._clients[client_id].verification_status = "expired"
        
        logger.info(f"Found {expired_count} clients with expired compliance")
        return expired_count