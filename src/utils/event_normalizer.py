"""
Unified Event Normalizer

Provides consistent event normalization across all stages (Stage 1, 2, 3, 4).
Ensures all field name variants are available for compatibility.
"""

import logging
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger("event_normalizer")


class EventNormalizer:
    """
    Unified event normalizer that standardizes field names across all stages.
    
    Ensures:
    - All ProcessID variants are available (ProcessID, ProcessId, process_id, pid)
    - All EventID variants are available (EventID, event_id)
    - All common field variants are normalized
    - Missing fields are handled gracefully
    """
    
    # Field mappings: (primary_key, [variant_keys])
    FIELD_MAPPINGS = {
        # Process ID variants
        "ProcessID": ["ProcessId", "process_id", "pid"],
        # Event ID variants
        "EventID": ["event_id", "EventId"],
        # Process GUID variants
        "ProcessGuid": ["process_guid"],
        # Image/Executable path variants
        "Image": ["image", "ImagePath", "image_path"],
        # Command line variants
        "CommandLine": ["command_line", "CommandLine"],
        # Parent process variants
        "ParentProcessId": ["parent_process_id", "ParentPID", "ppid"],
        "ParentProcessGuid": ["parent_process_guid"],
        "ParentImage": ["parent_image"],
        "ParentCommandLine": ["parent_command_line"],
        # Target filename variants
        "TargetFilename": ["target_filename", "TargetFile"],
        # Destination IP/Port variants
        "DestinationIp": ["destination_ip", "DestinationIP"],
        "DestinationPort": ["destination_port", "DestinationPort"],
        # Source IP/Port variants
        "SourceIp": ["source_ip", "SourceIP"],
        "SourcePort": ["source_port", "SourcePort"],
        # Protocol variants
        "Protocol": ["protocol"],
        # User variants
        "User": ["user", "UserName"],
        # Timestamp variants
        "UtcTime": ["utc_time", "UtcTime"],
        "timestamp": ["Timestamp", "TimeCreated"],
    }
    
    @classmethod
    def normalize(cls, event: Dict[str, Any], strict: bool = False) -> Dict[str, Any]:
        """
        Normalize an event to ensure all field variants are available.
        
        Args:
            event: Event dictionary to normalize
            strict: If True, raise errors on missing required fields. If False, handle gracefully.
            
        Returns:
            Normalized event dictionary with all variants
        """
        normalized = dict(event)  # Start with copy
        
        # Normalize each field group
        for primary_key, variant_keys in cls.FIELD_MAPPINGS.items():
            # Find the value from any variant
            value = None
            source_key = None
            
            # Check primary key first
            if primary_key in normalized:
                value = normalized[primary_key]
                source_key = primary_key
            else:
                # Check variants
                for variant in variant_keys:
                    if variant in normalized:
                        value = normalized[variant]
                        source_key = variant
                        break
            
            # If value found, populate all variants
            if value is not None:
                # Set primary key
                normalized[primary_key] = value
                # Set all variants
                for variant in variant_keys:
                    if variant not in normalized:
                        normalized[variant] = value
            elif strict and primary_key in ["ProcessID", "EventID"]:
                # Required fields missing
                logger.warning(f"Event normalization: Missing required field {primary_key}")
        
        # Special handling for ProcessID - ensure it's an integer
        if "ProcessID" in normalized:
            try:
                pid = int(normalized["ProcessID"])
                normalized["ProcessID"] = pid
                normalized["ProcessId"] = pid
                normalized["process_id"] = pid
                normalized["pid"] = pid
            except (ValueError, TypeError):
                if strict:
                    raise ValueError(f"Invalid ProcessID value: {normalized.get('ProcessID')}")
                logger.debug(f"Could not convert ProcessID to int: {normalized.get('ProcessID')}")
        
        # Special handling for EventID - ensure it's an integer
        if "EventID" in normalized:
            try:
                event_id = int(normalized["EventID"])
                normalized["EventID"] = event_id
                normalized["event_id"] = event_id
            except (ValueError, TypeError):
                if strict:
                    raise ValueError(f"Invalid EventID value: {normalized.get('EventID')}")
                logger.debug(f"Could not convert EventID to int: {normalized.get('EventID')}")
        
        # Special handling for ParentProcessId - ensure it's an integer if present
        if "ParentProcessId" in normalized and normalized["ParentProcessId"]:
            try:
                ppid = int(normalized["ParentProcessId"])
                normalized["ParentProcessId"] = ppid
                normalized["parent_process_id"] = ppid
            except (ValueError, TypeError):
                # Not critical, just log
                logger.debug(f"Could not convert ParentProcessId to int: {normalized.get('ParentProcessId')}")
        
        return normalized
    
    @classmethod
    def validate(cls, event: Dict[str, Any], required_fields: Optional[list] = None) -> Tuple[bool, List[str]]:
        """
        Validate that an event has required fields.
        
        Args:
            event: Event dictionary to validate
            required_fields: List of required field names (default: ["ProcessID", "EventID"])
            
        Returns:
            Tuple of (is_valid: bool, missing_fields: list[str])
        """
        if required_fields is None:
            required_fields = ["ProcessID", "EventID"]
        
        missing = []
        for field in required_fields:
            # Check primary key and variants
            found = False
            if field in event:
                found = True
            else:
                # Check variants
                for primary, variants in cls.FIELD_MAPPINGS.items():
                    if primary == field:
                        for variant in variants:
                            if variant in event:
                                found = True
                                break
                        break
            
            if not found:
                missing.append(field)
        
        return len(missing) == 0, missing
    
    @classmethod
    def get_field_value(cls, event: Dict[str, Any], field_name: str, default: Any = None) -> Any:
        """
        Get a field value from an event, checking all variants.
        
        Args:
            event: Event dictionary
            field_name: Primary field name
            default: Default value if field not found
            
        Returns:
            Field value or default
        """
        # Check primary key
        if field_name in event:
            return event[field_name]
        
        # Check variants
        for primary, variants in cls.FIELD_MAPPINGS.items():
            if primary == field_name:
                for variant in variants:
                    if variant in event:
                        return event[variant]
                break
        
        return default
    
    @classmethod
    def ensure_pid_variants(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure all ProcessID variants are present in the event.
        Quick normalization for just PID fields.
        
        Args:
            event: Event dictionary
            
        Returns:
            Event with all PID variants
        """
        pid = cls.get_field_value(event, "ProcessID")
        if pid is not None:
            try:
                pid = int(pid)
                event["ProcessID"] = pid
                event["ProcessId"] = pid
                event["process_id"] = pid
                event["pid"] = pid
            except (ValueError, TypeError):
                pass
        
        return event
    
    @classmethod
    def ensure_eventid_variants(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure all EventID variants are present in the event.
        Quick normalization for just EventID fields.
        
        Args:
            event: Event dictionary
            
        Returns:
            Event with all EventID variants
        """
        event_id = cls.get_field_value(event, "EventID")
        if event_id is not None:
            try:
                event_id = int(event_id)
                event["EventID"] = event_id
                event["event_id"] = event_id
            except (ValueError, TypeError):
                pass
        
        return event

