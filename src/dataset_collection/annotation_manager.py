"""
Annotation Manager

Manages labeling and annotation of features for dataset creation.
Provides threat classification and confidence scoring.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


logger = logging.getLogger(__name__)


class ThreatLabel(Enum):
    """Threat classification labels"""
    BENIGN = "benign"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    C2_COMMUNICATION = "c2_communication"
    SUSPICIOUS = "suspicious"


class AnnotationManager:
    """
    Manages annotation and labeling of features
    
    Provides:
    - Feature labeling with threat types
    - Confidence scoring
    - Bulk annotation
    - Statistics tracking
    """

    def __init__(self, session_dir: str):
        """
        Initialize AnnotationManager
        
        Args:
            session_dir: Path to dataset collection session directory
        """
        self.session_dir = Path(session_dir)
        self.annotations_file = self.session_dir / "annotations" / "annotations.json"
        self.annotations = self._load_annotations()
        logger.info(f"AnnotationManager initialized for {session_dir}")

    def add_annotation(self, feature_id: str, threat_type: ThreatLabel,
                      confidence: float, notes: str = "", tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Add annotation for a feature
        
        Args:
            feature_id: Unique identifier of the feature
            threat_type: ThreatLabel enum value
            confidence: Confidence score (0.0 to 1.0)
            notes: Optional notes about the annotation
            tags: Optional list of tags
            
        Returns:
            Annotation dictionary
            
        Raises:
            ValueError: If confidence is invalid or threat_type is invalid
        """
        try:
            if not (0.0 <= confidence <= 1.0):
                raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}")
            
            if not isinstance(threat_type, ThreatLabel):
                raise ValueError(f"Invalid threat_type: {threat_type}")
            
            annotation = {
                'feature_id': feature_id,
                'threat_type': threat_type.value,
                'confidence': confidence,
                'notes': notes,
                'tags': tags or [],
                'annotated_at': datetime.now().isoformat()
            }
            
            self.annotations[feature_id] = annotation
            self._save_annotations()
            logger.debug(f"Annotation added for feature {feature_id[:8]}: {threat_type.value} ({confidence})")
            
            return annotation
        except Exception as e:
            logger.error(f"Error adding annotation: {e}")
            raise

    def bulk_annotate(self, annotations_list: List[Dict]) -> int:
        """
        Add multiple annotations at once
        
        Args:
            annotations_list: List of annotation dictionaries with keys:
                - feature_id: str
                - threat_type: str (must match ThreatLabel values)
                - confidence: float
                - notes: str (optional)
                - tags: List[str] (optional)
        
        Returns:
            Number of successfully added annotations
        """
        success_count = 0
        
        for annotation in annotations_list:
            try:
                feature_id = annotation['feature_id']
                threat_type = ThreatLabel(annotation['threat_type'])
                confidence = annotation['confidence']
                notes = annotation.get('notes', '')
                tags = annotation.get('tags', [])
                
                self.add_annotation(feature_id, threat_type, confidence, notes, tags)
                success_count += 1
            except Exception as e:
                logger.error(f"Error in bulk annotation: {e}")
                continue
        
        logger.info(f"Bulk annotation completed: {success_count}/{len(annotations_list)} successful")
        return success_count

    def get_annotation(self, feature_id: str) -> Optional[Dict[str, Any]]:
        """
        Get annotation for a feature
        
        Args:
            feature_id: Feature identifier
            
        Returns:
            Annotation dictionary or None if not found
        """
        return self.annotations.get(feature_id, None)

    def get_all_annotations(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all annotations
        
        Returns:
            Dictionary mapping feature_id to annotation
        """
        return self.annotations.copy()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get annotation statistics
        
        Returns:
            Dictionary with annotation statistics
        """
        stats = {
            'total_annotated': len(self.annotations),
            'by_threat_type': {},
            'confidence_stats': {
                'avg': 0.0,
                'min': 1.0,
                'max': 0.0
            },
            'tagged_features': 0
        }
        
        if not self.annotations:
            return stats
        
        confidence_values = []
        
        for annotation in self.annotations.values():
            threat_type = annotation['threat_type']
            stats['by_threat_type'][threat_type] = stats['by_threat_type'].get(threat_type, 0) + 1
            
            confidence = annotation['confidence']
            confidence_values.append(confidence)
            
            if annotation.get('tags'):
                stats['tagged_features'] += 1
        
        if confidence_values:
            stats['confidence_stats']['avg'] = sum(confidence_values) / len(confidence_values)
            stats['confidence_stats']['min'] = min(confidence_values)
            stats['confidence_stats']['max'] = max(confidence_values)
        
        return stats

    def get_annotations_by_threat_type(self, threat_type: ThreatLabel) -> List[Dict[str, Any]]:
        """
        Get all annotations of a specific threat type
        
        Args:
            threat_type: ThreatLabel to filter by
            
        Returns:
            List of annotations
        """
        return [
            ann for ann in self.annotations.values()
            if ann['threat_type'] == threat_type.value
        ]

    def update_annotation(self, feature_id: str, threat_type: Optional[ThreatLabel] = None,
                         confidence: Optional[float] = None, notes: Optional[str] = None,
                         tags: Optional[List[str]] = None) -> bool:
        """
        Update existing annotation
        
        Args:
            feature_id: Feature to update
            threat_type: New threat type (optional)
            confidence: New confidence (optional)
            notes: New notes (optional)
            tags: New tags (optional)
            
        Returns:
            True if update was successful
        """
        try:
            if feature_id not in self.annotations:
                logger.warning(f"Feature {feature_id} not found for update")
                return False
            
            annotation = self.annotations[feature_id]
            
            if threat_type is not None:
                annotation['threat_type'] = threat_type.value
            if confidence is not None:
                if not (0.0 <= confidence <= 1.0):
                    raise ValueError(f"Invalid confidence: {confidence}")
                annotation['confidence'] = confidence
            if notes is not None:
                annotation['notes'] = notes
            if tags is not None:
                annotation['tags'] = tags
            
            annotation['updated_at'] = datetime.now().isoformat()
            self._save_annotations()
            
            logger.debug(f"Annotation updated for feature {feature_id[:8]}")
            return True
        except Exception as e:
            logger.error(f"Error updating annotation: {e}")
            return False

    def export_annotations(self, output_file: str, format: str = "json") -> str:
        """
        Export annotations to file
        
        Args:
            output_file: Path to output file
            format: Export format (json or csv)
            
        Returns:
            Path to exported file
        """
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == "json":
                with open(output_path, 'w') as f:
                    json.dump(self.annotations, f, indent=2)
            elif format == "csv":
                import csv
                with open(output_path, 'w', newline='') as f:
                    if self.annotations:
                        fieldnames = list(self.annotations[next(iter(self.annotations))].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for annotation in self.annotations.values():
                            writer.writerow(annotation)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            logger.info(f"Annotations exported to {output_file}")
            return str(output_path)
        except Exception as e:
            logger.error(f"Error exporting annotations: {e}")
            raise

    def _load_annotations(self) -> Dict[str, Dict[str, Any]]:
        """Load existing annotations from file"""
        try:
            if self.annotations_file.exists():
                with open(self.annotations_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load annotations: {e}")
        
        return {}

    def _save_annotations(self) -> None:
        """Save annotations to file"""
        try:
            self.annotations_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.annotations_file, 'w') as f:
                json.dump(self.annotations, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving annotations: {e}")
            raise

    def __repr__(self) -> str:
        """String representation"""
        return f"AnnotationManager(total_annotations={len(self.annotations)})"
