"""
Simple console audit logger for demonstration purposes.
"""

import logging
from datetime import datetime
from typing import Any, Dict

logger = logging.getLogger(__name__)


class ConsoleAuditLogger:
    """Simple audit logger that outputs to console."""
    
    def __init__(self):
        self.logs = []
    
    def log(self, message: str, context: Dict[str, Any] = None):
        """Log a message with optional context."""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "message": message,
            "context": context or {}
        }
        
        self.logs.append(log_entry)
        
        # Print to console
        print(f"[AUDIT {timestamp}] {message}")
        if context:
            for key, value in context.items():
                print(f"  {key}: {value}")
    
    def log_poa_creation(self, poa_id: str, principal: str, client: str):
        """Log PoA creation event."""
        self.log(
            f"PoA Created: {poa_id}",
            {
                "event_type": "poa_creation",
                "poa_id": poa_id,
                "principal": principal,
                "client": client
            }
        )
    
    def log_poa_validation(self, poa_id: str, status: str):
        """Log PoA validation event."""
        self.log(
            f"PoA Validated: {poa_id} - Status: {status}",
            {
                "event_type": "poa_validation",
                "poa_id": poa_id,
                "validation_status": status
            }
        )
    
    def log_token_creation(self, token_id: str, poa_id: str):
        """Log token creation event."""
        self.log(
            f"Token Created: {token_id} for PoA: {poa_id}",
            {
                "event_type": "token_creation",
                "token_id": token_id,
                "poa_id": poa_id
            }
        )
    
    def log_poa_usage(self, poa_id: str, action: str, context: Dict[str, Any] = None):
        """Log PoA usage event."""
        self.log(
            f"PoA Used: {poa_id} - Action: {action}",
            {
                "event_type": "poa_usage",
                "poa_id": poa_id,
                "action": action,
                **(context or {})
            }
        )
    
    def get_logs(self):
        """Get all logged entries."""
        return self.logs.copy()