"""
Audit logging module for GAuth protocol compliance.

Copyright (c) 2025 Gimel Foundation and the persons identified as the document authors.
All rights reserved. This file is subject to the Gimel Foundation's Legal Provisions Relating to GiFo Documents.
See http://GimelFoundation.com or https://github.com/Gimel-Foundation for details.
Code Components extracted from GiFo-RfC 0111 must include this license text and are provided without warranty.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import json
from collections import deque

from ..core.types import AuditEvent


class AuditLogger(ABC):
    """Abstract base class for audit logging"""

    @abstractmethod
    async def log(self, event: AuditEvent) -> None:
        """Log an audit event"""
        pass

    @abstractmethod
    async def get_events(
        self,
        client_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditEvent]:
        """Retrieve audit events with optional filtering"""
        pass

    async def close(self) -> None:
        """Close the audit logger and release resources"""
        pass


class MemoryAuditLogger(AuditLogger):
    """In-memory audit logger for development and testing"""

    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self.events: deque = deque(maxlen=max_entries)
        self._lock = asyncio.Lock()

    async def log(self, event: AuditEvent) -> None:
        """Log an audit event to memory"""
        async with self._lock:
            self.events.append(event)

    async def get_events(
        self,
        client_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditEvent]:
        """Retrieve audit events with optional filtering"""
        async with self._lock:
            filtered_events = []
            
            for event in self.events:
                # Filter by client_id
                if client_id and event.client_id != client_id:
                    continue
                
                # Filter by event_type
                if event_type and event.event_type != event_type:
                    continue
                
                # Filter by start_time
                if start_time and event.timestamp < start_time:
                    continue
                
                # Filter by end_time
                if end_time and event.timestamp > end_time:
                    continue
                
                filtered_events.append(event)
            
            return filtered_events


class FileAuditLogger(AuditLogger):
    """File-based audit logger for persistent storage"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._lock = asyncio.Lock()

    async def log(self, event: AuditEvent) -> None:
        """Log an audit event to file"""
        async with self._lock:
            event_data = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "client_id": event.client_id,
                "timestamp": event.timestamp.isoformat(),
                "details": event.details,
                "principal": event.principal,
                "resource": event.resource,
            }
            
            try:
                with open(self.file_path, "a") as f:
                    f.write(json.dumps(event_data) + "\n")
            except Exception as e:
                # In a production system, you might want to handle this differently
                print(f"Failed to write audit log: {e}")

    async def get_events(
        self,
        client_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditEvent]:
        """Retrieve audit events from file with optional filtering"""
        events = []
        
        try:
            with open(self.file_path, "r") as f:
                for line in f:
                    try:
                        event_data = json.loads(line.strip())
                        
                        # Convert timestamp back to datetime
                        timestamp = datetime.fromisoformat(event_data["timestamp"])
                        
                        # Create AuditEvent object
                        event = AuditEvent(
                            event_id=event_data["event_id"],
                            event_type=event_data["event_type"],
                            client_id=event_data["client_id"],
                            timestamp=timestamp,
                            details=event_data["details"],
                            principal=event_data.get("principal"),
                            resource=event_data.get("resource"),
                        )
                        
                        # Apply filters
                        if client_id and event.client_id != client_id:
                            continue
                        
                        if event_type and event.event_type != event_type:
                            continue
                        
                        if start_time and event.timestamp < start_time:
                            continue
                        
                        if end_time and event.timestamp > end_time:
                            continue
                        
                        events.append(event)
                        
                    except (json.JSONDecodeError, KeyError) as e:
                        # Skip malformed lines
                        continue
                        
        except FileNotFoundError:
            # Return empty list if file doesn't exist
            pass
        
        return events


# Factory function for creating audit loggers
def create_audit_logger(logger_type: str = "memory", **kwargs) -> AuditLogger:
    """
    Factory function to create audit loggers
    
    Args:
        logger_type: Type of logger ("memory" or "file")
        **kwargs: Additional arguments for the logger
        
    Returns:
        AuditLogger instance
    """
    if logger_type == "memory":
        max_entries = kwargs.get("max_entries", 1000)
        return MemoryAuditLogger(max_entries)
    elif logger_type == "file":
        file_path = kwargs.get("file_path", "audit.log")
        return FileAuditLogger(file_path)
    else:
        raise ValueError(f"Unknown logger type: {logger_type}")


# Default logger for convenience
def new_logger(max_entries: int = 1000) -> AuditLogger:
    """Create a new in-memory audit logger (for Go compatibility)"""
    return MemoryAuditLogger(max_entries)