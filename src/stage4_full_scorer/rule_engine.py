"""
Rule Engine for Stage 4

Custom behavioral rules for ransomware detection.
Note: YARA scanning has been moved to Stage 3 for faster detection.
"""

import logging
import os
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("stage4_rule_engine")


class RulePriority(Enum):
    """Rule priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class RuleMatch:
    """Result from rule matching"""
    rule_name: str
    priority: RulePriority
    matched: bool
    confidence: float
    details: Dict[str, Any]


class RuleEngine:
    """
    Rule-based detection engine.
    
    Features:
    - Custom behavioral rules
    - Rule priority system
    - Composite rule conditions
    
    Note: YARA scanning has been moved to Stage 3 for faster detection.
    """
    
    def __init__(self):
        """
        Initialize Rule Engine.
        """
        self.custom_rules = []
        
        # Initialize custom rules
        self._initialize_custom_rules()
        
        logger.info("RuleEngine initialized (YARA moved to Stage 3)")
    
    def _initialize_custom_rules(self) -> None:
        """Initialize custom behavioral rules for ransomware"""
        
        # Rule 1: Rapid file encryption pattern
        self.custom_rules.append({
            'name': 'rapid_file_encryption',
            'priority': RulePriority.CRITICAL,
            'condition': lambda features: (
                features.get('files_modified', 0) > 50 and
                features.get('entropy_trend', 0) > 7.5 and
                features.get('burst_detection_score', 0) > 7.0
            ),
            'confidence': 0.95
        })
        
        # Rule 2: Extension change pattern
        self.custom_rules.append({
            'name': 'extension_change_pattern',
            'priority': RulePriority.HIGH,
            'condition': lambda features: (
                features.get('file_extension_anomaly', 0) > 10 and
                features.get('file_rename_patterns', 0) > 20
            ),
            'confidence': 0.85
        })
        
        # Rule 3: Honeypot access
        self.custom_rules.append({
            'name': 'honeypot_access',
            'priority': RulePriority.CRITICAL,
            'condition': lambda features: features.get('suspicious_honeypot_access', 0) > 0,
            'confidence': 0.99
        })
        
        # Rule 4: Process hollowing indicators
        self.custom_rules.append({
            'name': 'process_hollowing',
            'priority': RulePriority.HIGH,
            'condition': lambda features: (
                features.get('process_created_suspended', 0) > 0 or
                features.get('ntunmapviewofsection_usage', 0) > 0 or
                features.get('large_writeprocessmemory_activity', 0) > 5
            ),
            'confidence': 0.80
        })
        
        # Rule 5: Shadow copy deletion
        self.custom_rules.append({
            'name': 'shadow_copy_deletion',
            'priority': RulePriority.CRITICAL,
            'condition': lambda features: (
                'shadow_copy_deletion_cmdline' in str(features.get('__reasons', []))
            ),
            'confidence': 0.98
        })
        
        # Rule 6: Ransomware extension pattern
        self.custom_rules.append({
            'name': 'ransomware_extension',
            'priority': RulePriority.HIGH,
            'condition': lambda features: (
                'ransom_extension_detected' in str(features.get('__reasons', []))
            ),
            'confidence': 0.90
        })
        
        # Rule 7: High entropy with network activity
        self.custom_rules.append({
            'name': 'high_entropy_network',
            'priority': RulePriority.MEDIUM,
            'condition': lambda features: (
                features.get('entropy_trend', 0) > 7.5 and
                features.get('network_connections', 0) > 5 and
                features.get('unusual_destination_ip_behavior', 0) > 0
            ),
            'confidence': 0.70
        })
        
        # Rule 8: Memory anomalies with file I/O
        self.custom_rules.append({
            'name': 'memory_file_anomaly',
            'priority': RulePriority.MEDIUM,
            'condition': lambda features: (
                features.get('writexecutable_memory_regions', 0) > 0 and
                features.get('files_modified', 0) > 30
            ),
            'confidence': 0.75
        })
    
    def evaluate(
        self,
        event: Dict[str, Any],
        features: Dict[str, float],
        file_path: Optional[str] = None
    ) -> List[RuleMatch]:
        """
        Evaluate event against all rules.
        
        Args:
            event: Event dictionary
            features: Combined features from all stages (includes YARA results from Stage 3)
            file_path: Optional file path (not used for YARA, kept for compatibility)
            
        Returns:
            List of RuleMatch objects
        """
        matches = []
        
        # Note: YARA scanning is now done in Stage 3
        # YARA results are available in features['yara_match'] and event['__stage3_yara_matched']
        
        # Custom rule evaluation
        for rule in self.custom_rules:
            try:
                if rule['condition'](features):
                    matches.append(RuleMatch(
                        rule_name=rule['name'],
                        priority=rule['priority'],
                        matched=True,
                        confidence=rule['confidence'],
                        details={}
                    ))
            except Exception as e:
                logger.debug(f"Custom rule evaluation error for {rule['name']}: {e}")
        
        # Sort by priority
        matches.sort(key=lambda x: x.priority.value)
        
        return matches
    
    def get_highest_priority_match(self, matches: List[RuleMatch]) -> Optional[RuleMatch]:
        """Get the highest priority match from a list"""
        if not matches:
            return None
        return min(matches, key=lambda x: x.priority.value)
    
    def should_override_ml(self, matches: List[RuleMatch]) -> bool:
        """
        Determine if rule matches should override ML classification.
        
        Critical and high priority rules can override ML.
        """
        if not matches:
            return False
        
        highest = self.get_highest_priority_match(matches)
        return highest and highest.priority in [RulePriority.CRITICAL, RulePriority.HIGH]

