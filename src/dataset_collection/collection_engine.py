"""
Dataset Collection Engine

Orchestrates the collection and processing of events for dataset creation.
Handles feature extraction, storage, and dataset materialization.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import uuid


logger = logging.getLogger(__name__)


class DatasetCollectionEngine:
    """
    Manages dataset collection workflow
    
    Orchestrates:
    - Event collection and storage
    - Feature extraction
    - Dataset materialization
    - Session management
    """

    def __init__(self, session_id: str, session_name: str, output_dir: str = "data/dataset_sessions"):
        """
        Initialize DatasetCollectionEngine
        
        Args:
            session_id: Unique session identifier
            session_name: Human-readable session name
            output_dir: Base directory for session data
        """
        self.session_id = session_id
        self.session_name = session_name
        self.output_dir = Path(output_dir)
        self.session_dir = self.output_dir / session_name
        
        # Setup directories
        self._setup_directories()
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Session metadata
        self.metadata = {
            'session_id': session_id,
            'session_name': session_name,
            'start_time': datetime.now().isoformat(),
            'status': 'initialized',
            'raw_events_count': 0,
            'extracted_features_count': 0,
            'labeled_count': 0,
            'version': '1.0'
        }
        
        self._save_metadata()
        self.logger.info(f"DatasetCollectionEngine initialized: {session_name}")

    def _setup_directories(self) -> None:
        """Create session directory structure"""
        directories = [
            self.session_dir,
            self.session_dir / "raw_logs",
            self.session_dir / "extracted_features",
            self.session_dir / "dataset",
            self.session_dir / "labels",
            self.session_dir / "annotations",
            self.session_dir / "logs"
        ]
        
        for dir_path in directories:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise RuntimeError(f"Failed to create directory {dir_path}: {e}")

    def _setup_logging(self) -> logging.Logger:
        """Setup dedicated logging for this session"""
        log_file = self.session_dir / "logs" / "collection.log"
        logger_name = f"dataset_{self.session_id[:8]}"
        logger = logging.getLogger(logger_name)
        
        # Remove existing handlers to prevent duplicates
        logger.handlers = []
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
        return logger

    def start_collection(self) -> str:
        """
        Start a new collection session
        
        Returns:
            Session ID
        """
        try:
            self.metadata['status'] = 'active'
            self._save_metadata()
            self.logger.info(f"Collection session started: {self.session_name}")
            return self.session_id
        except Exception as e:
            self.logger.error(f"Error starting collection: {e}")
            raise

    def process_raw_events(self, raw_events: List[Dict]) -> List[Dict]:
        """
        Process raw events and store them
        
        Args:
            raw_events: List of raw event dictionaries from Sysmon
            
        Returns:
            List of raw events (for tracking)
        """
        if not raw_events:
            self.logger.warning("No raw events to process")
            return []
        
        try:
            self.logger.info(f"Processing {len(raw_events)} raw events")
            
            # Store raw logs with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            raw_log_file = self.session_dir / "raw_logs" / f"raw_events_{timestamp}.jsonl"
            
            self._store_jsonl_file(raw_events, raw_log_file)
            self.metadata['raw_events_count'] += len(raw_events)
            self._save_metadata()
            
            self.logger.info(f"Stored {len(raw_events)} raw events to {raw_log_file.name}")
            return raw_events
        except Exception as e:
            self.logger.error(f"Error processing raw events: {e}")
            raise

    def store_extracted_features(self, features: List[Dict]) -> str:
        """
        Store extracted feature vectors
        
        Args:
            features: List of extracted feature dictionaries
            
        Returns:
            Path to feature file
        """
        if not features:
            self.logger.warning("No features to store")
            return ""
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            feature_file = self.session_dir / "extracted_features" / f"features_{timestamp}.jsonl"
            
            self._store_jsonl_file(features, feature_file)
            self.metadata['extracted_features_count'] += len(features)
            self._save_metadata()
            
            self.logger.info(f"Stored {len(features)} feature vectors to {feature_file.name}")
            return str(feature_file)
        except Exception as e:
            self.logger.error(f"Error storing features: {e}")
            raise

    def add_label(self, feature_id: str, label: Dict) -> bool:
        """
        Add label/annotation to a feature
        
        Args:
            feature_id: ID of the feature to label
            label: Label dictionary with keys:
                - threat_type: str (benign, ransomware, trojan, etc.)
                - confidence: float (0.0 to 1.0)
                - notes: str (optional)
                - tags: List[str] (optional)
            
        Returns:
            True if successful
        """
        try:
            if not label.get('threat_type'):
                raise ValueError("Label must include 'threat_type'")
            
            confidence = label.get('confidence', 0.0)
            if not (0.0 <= confidence <= 1.0):
                raise ValueError("Confidence must be between 0.0 and 1.0")
            
            label_entry = {
                'feature_id': feature_id,
                'threat_type': label['threat_type'],
                'confidence': confidence,
                'notes': label.get('notes', ''),
                'tags': label.get('tags', []),
                'labeled_at': datetime.now().isoformat()
            }
            
            label_file = self.session_dir / "labels" / f"labels_{datetime.now().strftime('%Y%m%d')}.jsonl"
            
            with open(label_file, 'a') as f:
                f.write(json.dumps(label_entry) + '\n')
            
            self.metadata['labeled_count'] += 1
            self._save_metadata()
            self.logger.debug(f"Added label for feature {feature_id[:8]}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding label: {e}")
            return False

    def create_dataset(self, output_format: str = "jsonl") -> str:
        """
        Create unified dataset from extracted features and labels
        
        Args:
            output_format: Format (jsonl or parquet)
            
        Returns:
            Path to created dataset
        """
        try:
            self.logger.info("Creating unified dataset...")
            
            # Load all features
            all_features = []
            features_dir = self.session_dir / "extracted_features"
            
            if not features_dir.exists():
                raise FileNotFoundError(f"Features directory not found: {features_dir}")
            
            for feature_file in sorted(features_dir.glob("*.jsonl")):
                with open(feature_file, 'r') as f:
                    for line in f:
                        all_features.append(json.loads(line))
            
            # Load all labels
            labels_map = {}
            labels_dir = self.session_dir / "labels"
            
            if labels_dir.exists():
                for label_file in labels_dir.glob("*.jsonl"):
                    with open(label_file, 'r') as f:
                        for line in f:
                            entry = json.loads(line)
                            labels_map[entry['feature_id']] = {
                                'threat_type': entry.get('threat_type'),
                                'confidence': entry.get('confidence'),
                                'notes': entry.get('notes'),
                                'tags': entry.get('tags', [])
                            }
            
            # Merge features with labels
            dataset = []
            for feature in all_features:
                feature_id = feature.get('feature_id', str(uuid.uuid4()))
                feature['label'] = labels_map.get(feature_id, None)
                dataset.append(feature)
            
            # Store dataset
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dataset_file = self.session_dir / "dataset" / f"dataset_{self.session_name}_{timestamp}.{output_format}"
            
            if output_format == "jsonl":
                self._store_jsonl_file(dataset, dataset_file)
            else:
                raise ValueError(f"Unsupported format: {output_format}")
            
            # Create dataset manifest
            manifest = {
                'session_id': self.session_id,
                'dataset_file': str(dataset_file),
                'record_count': len(dataset),
                'labeled_count': len([d for d in dataset if d.get('label')]),
                'unlabeled_count': len([d for d in dataset if not d.get('label')]),
                'created_at': datetime.now().isoformat()
            }
            
            manifest_file = self.session_dir / "dataset" / "manifest.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            self.logger.info(f"Dataset created: {len(dataset)} records at {dataset_file.name}")
            return str(dataset_file)
        except Exception as e:
            self.logger.error(f"Error creating dataset: {e}")
            raise

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session"""
        return {
            'session_id': self.session_id,
            'session_name': self.session_name,
            'status': self.metadata['status'],
            'raw_events': self.metadata['raw_events_count'],
            'extracted_features': self.metadata['extracted_features_count'],
            'labeled': self.metadata['labeled_count'],
            'session_dir': str(self.session_dir)
        }

    def _store_jsonl_file(self, data: List[Dict], file_path: Path) -> None:
        """Store data as JSONL file"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w') as f:
                for item in data:
                    f.write(json.dumps(item) + '\n')
        except Exception as e:
            raise IOError(f"Failed to write JSONL file {file_path}: {e}")

    def _save_metadata(self) -> None:
        """Save session metadata"""
        try:
            metadata_file = self.session_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving metadata: {e}")

    def finalize_session(self) -> None:
        """Finalize collection session"""
        try:
            self.metadata['status'] = 'completed'
            self.metadata['end_time'] = datetime.now().isoformat()
            self._save_metadata()
            self.logger.info(f"Session finalized: {self.session_name}")
        except Exception as e:
            self.logger.error(f"Error finalizing session: {e}")
            raise

    def __repr__(self) -> str:
        """String representation"""
        return f"DatasetCollectionEngine(session={self.session_name}, status={self.metadata['status']})"
