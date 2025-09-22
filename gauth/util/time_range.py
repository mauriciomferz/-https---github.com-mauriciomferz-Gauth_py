"""
Time range utilities for GAuth framework.
Provides time-based window management and validation.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
import re


@dataclass
class TimeRangeInput:
    """Input structure for parsing time ranges from strings."""
    start: Optional[str] = None
    end: Optional[str] = None


class TimeRange:
    """Represents a time-based window with start and end times."""
    
    def __init__(self, start: Optional[datetime] = None, end: Optional[datetime] = None):
        self.start = start
        self.end = end
        
        # Validate that start comes before end if both are provided
        if self.start and self.end and self.start >= self.end:
            raise ValueError("Start time must be before end time")
    
    def contains(self, t: datetime) -> bool:
        """Check if a given time is within the time range."""
        if self.start and t < self.start:
            return False
        
        if self.end and t > self.end:
            return False
        
        return True
    
    def is_allowed(self, t: datetime) -> Tuple[bool, str]:
        """
        Check if the given time falls within the time range.
        Returns (allowed, message) tuple.
        """
        if self.start and t < self.start:
            return False, "Action not allowed before specified start time"
        
        if self.end and t > self.end:
            return False, "Action not allowed after specified end time"
        
        return True, ""
    
    def duration(self) -> Optional[timedelta]:
        """Return the duration of the time range."""
        if not self.start or not self.end:
            return None
        return self.end - self.start
    
    def is_active(self, now: Optional[datetime] = None) -> bool:
        """Check if the time range is currently active."""
        if now is None:
            now = datetime.now()
        return self.contains(now)
    
    def time_until_start(self, now: Optional[datetime] = None) -> Optional[timedelta]:
        """Calculate time until the range starts."""
        if not self.start:
            return None
        
        if now is None:
            now = datetime.now()
        
        if now >= self.start:
            return timedelta(0)
        
        return self.start - now
    
    def time_until_end(self, now: Optional[datetime] = None) -> Optional[timedelta]:
        """Calculate time until the range ends."""
        if not self.end:
            return None
        
        if now is None:
            now = datetime.now()
        
        if now >= self.end:
            return timedelta(0)
        
        return self.end - now
    
    def overlaps(self, other: 'TimeRange') -> bool:
        """Check if this time range overlaps with another."""
        # If either range is unbounded, they overlap
        if (not self.start or not self.end or 
            not other.start or not other.end):
            return True
        
        # Check for non-overlapping conditions
        if self.end <= other.start or other.end <= self.start:
            return False
        
        return True
    
    def intersect(self, other: 'TimeRange') -> Optional['TimeRange']:
        """Calculate the intersection of two time ranges."""
        if not self.overlaps(other):
            return None
        
        # Calculate intersection bounds
        start = None
        if self.start and other.start:
            start = max(self.start, other.start)
        elif self.start:
            start = self.start
        elif other.start:
            start = other.start
        
        end = None
        if self.end and other.end:
            end = min(self.end, other.end)
        elif self.end:
            end = self.end
        elif other.end:
            end = other.end
        
        # Ensure valid range
        if start and end and start >= end:
            return None
        
        return TimeRange(start, end)
    
    def extend(self, delta: timedelta) -> 'TimeRange':
        """Extend the time range by the given delta on both ends."""
        new_start = self.start - delta if self.start else None
        new_end = self.end + delta if self.end else None
        return TimeRange(new_start, new_end)
    
    def shift(self, delta: timedelta) -> 'TimeRange':
        """Shift the entire time range by the given delta."""
        new_start = self.start + delta if self.start else None
        new_end = self.end + delta if self.end else None
        return TimeRange(new_start, new_end)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'start': self.start.isoformat() if self.start else None,
            'end': self.end.isoformat() if self.end else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TimeRange':
        """Create from dictionary representation."""
        start = None
        end = None
        
        if data.get('start'):
            start = datetime.fromisoformat(data['start'])
        
        if data.get('end'):
            end = datetime.fromisoformat(data['end'])
        
        return cls(start, end)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TimeRange':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def __str__(self) -> str:
        """String representation of the time range."""
        start_str = self.start.isoformat() if self.start else "unlimited"
        end_str = self.end.isoformat() if self.end else "unlimited"
        return f"[{start_str} to {end_str}]"
    
    def __repr__(self) -> str:
        return f"TimeRange(start={self.start!r}, end={self.end!r})"
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, TimeRange):
            return False
        return self.start == other.start and self.end == other.end
    
    def __hash__(self) -> int:
        return hash((self.start, self.end))


def create_time_range(start: Optional[datetime] = None, end: Optional[datetime] = None) -> TimeRange:
    """Create a new TimeRange instance."""
    return TimeRange(start, end)


def parse_time_range(input_data: TimeRangeInput) -> TimeRange:
    """Create a TimeRange from a TimeRangeInput."""
    start = None
    end = None
    
    if input_data.start:
        start = _parse_time_string(input_data.start)
    
    if input_data.end:
        end = _parse_time_string(input_data.end)
    
    return TimeRange(start, end)


def _parse_time_string(time_str: str) -> datetime:
    """Parse a time string in various formats."""
    time_str = time_str.strip()
    
    # Try ISO format first
    try:
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
    except ValueError:
        pass
    
    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Unable to parse time string: {time_str}")


def create_daily_time_range(start_hour: int, start_minute: int = 0, 
                           end_hour: int = 23, end_minute: int = 59) -> TimeRange:
    """Create a time range for daily recurring windows."""
    now = datetime.now()
    start = now.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
    end = now.replace(hour=end_hour, minute=end_minute, second=59, microsecond=999999)
    
    return TimeRange(start, end)


def create_business_hours() -> TimeRange:
    """Create a time range for standard business hours (9 AM to 5 PM)."""
    return create_daily_time_range(9, 0, 17, 0)


def create_duration_range(start: datetime, duration: timedelta) -> TimeRange:
    """Create a time range from a start time and duration."""
    return TimeRange(start, start + duration)


def create_relative_range(delta_start: timedelta, delta_end: timedelta, 
                         base_time: Optional[datetime] = None) -> TimeRange:
    """Create a time range relative to a base time (default: now)."""
    if base_time is None:
        base_time = datetime.now()
    
    start = base_time + delta_start
    end = base_time + delta_end
    
    return TimeRange(start, end)


def merge_time_ranges(ranges: list[TimeRange]) -> list[TimeRange]:
    """Merge overlapping time ranges into non-overlapping ranges."""
    if not ranges:
        return []
    
    # Sort ranges by start time (None values go to the end)
    sorted_ranges = sorted(ranges, key=lambda r: r.start if r.start else datetime.max)
    
    merged = [sorted_ranges[0]]
    
    for current in sorted_ranges[1:]:
        last = merged[-1]
        
        if last.overlaps(current):
            # Merge the ranges
            new_start = None
            if last.start and current.start:
                new_start = min(last.start, current.start)
            elif last.start:
                new_start = last.start
            elif current.start:
                new_start = current.start
            
            new_end = None
            if last.end and current.end:
                new_end = max(last.end, current.end)
            elif not last.end or not current.end:
                new_end = None  # Unbounded
            
            merged[-1] = TimeRange(new_start, new_end)
        else:
            merged.append(current)
    
    return merged