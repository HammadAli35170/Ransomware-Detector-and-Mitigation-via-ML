"""
Mode Configuration Management System

Manages system operational modes (Production vs Dataset Collection)
and persists configuration state.
"""

import os
import json
import logging
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict, Any
import uuid


logger = logging.getLogger(__name__)


class RunMode(Enum):
    """System operational modes"""
    PRODUCTION = "production"
    DATASET_COLLECTION = "dataset_collection"


@dataclass
class DatasetCollectionConfig:
    """Configuration for dataset collection mode"""
    enabled: bool = False
    session_name: str = ""
    session_id: str = ""
    capture_raw_logs: bool = True
    auto_feature_extract: bool = True
    store_features: bool = True
    output_dir: str = "data/dataset_sessions"
    archive_sysmon: bool = True
    include_metadata: bool = True
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetCollectionConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ProductionConfig:
    """Configuration for production mode"""
    enabled: bool = True
    ml_scoring: bool = True
    threshold: float = 90.0
    alert_on_detection: bool = True
    alert_output: str = "logs/alerts.log"
    skip_benign_filtering: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProductionConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ModeManager:
    """
    Manages system mode (production vs dataset collection)
    
    Provides mode-aware configuration and persistence.
    """

    def __init__(self, config_dir: str = "config"):
        """
        Initialize ModeManager
        
        Args:
            config_dir: Directory to store mode configuration
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_file = self.config_dir / "active_mode.json"
        self.current_mode = RunMode.PRODUCTION
        self.dataset_config = DatasetCollectionConfig()
        self.production_config = ProductionConfig()
        
        self._load_config()
        logger.info(f"ModeManager initialized in {self.current_mode.value} mode")

    def set_mode(self, mode: RunMode, session_name: Optional[str] = None) -> str:
        """
        Switch to specified mode
        
        Args:
            mode: Target mode (PRODUCTION or DATASET_COLLECTION)
            session_name: Session name for dataset collection mode
            
        Returns:
            Session ID if in dataset mode, otherwise empty string
        """
        try:
            self.current_mode = mode
            
            if mode == RunMode.DATASET_COLLECTION:
                if not session_name:
                    session_name = f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                session_id = str(uuid.uuid4())
                self.dataset_config.enabled = True
                self.dataset_config.session_name = session_name
                self.dataset_config.session_id = session_id
                self.dataset_config.created_at = datetime.now().isoformat()
                self.production_config.enabled = False
                
                logger.info(f"Switched to DATASET_COLLECTION mode: {session_name} ({session_id})")
                self._save_config()
                return session_id
            else:
                self.dataset_config.enabled = False
                self.production_config.enabled = True
                
                logger.info("Switched to PRODUCTION mode")
                self._save_config()
                return ""
        except Exception as e:
            logger.error(f"Error setting mode: {e}")
            raise

    def get_current_mode(self) -> RunMode:
        """Get current operational mode"""
        return self.current_mode

    def is_dataset_mode(self) -> bool:
        """Check if currently in dataset collection mode"""
        return self.current_mode == RunMode.DATASET_COLLECTION

    def is_production_mode(self) -> bool:
        """Check if currently in production mode"""
        return self.current_mode == RunMode.PRODUCTION

    def get_dataset_config(self) -> DatasetCollectionConfig:
        """Get dataset collection configuration"""
        if not self.dataset_config.enabled:
            logger.warning("Accessing dataset config while not in dataset mode")
        return self.dataset_config

    def get_production_config(self) -> ProductionConfig:
        """Get production configuration"""
        return self.production_config

    def get_status(self) -> Dict[str, Any]:
        """Get complete current configuration status"""
        return {
            'current_mode': self.current_mode.value,
            'timestamp': datetime.now().isoformat(),
            'dataset_config': self.dataset_config.to_dict() if self.dataset_config.enabled else None,
            'production_config': self.production_config.to_dict() if self.production_config.enabled else None
        }

    def _save_config(self) -> None:
        """Save current mode configuration to file"""
        try:
            config_data = self.get_status()
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            logger.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise

    def _load_config(self) -> None:
        """Load mode configuration from file if it exists"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    
                    mode_str = config.get('current_mode', 'production')
                    self.current_mode = RunMode(mode_str)
                    
                    if config.get('dataset_config'):
                        self.dataset_config = DatasetCollectionConfig.from_dict(config['dataset_config'])
                    
                    if config.get('production_config'):
                        self.production_config = ProductionConfig.from_dict(config['production_config'])
                    
                    logger.info(f"Configuration loaded from {self.config_file}")
            else:
                logger.debug(f"No existing configuration found at {self.config_file}")
                self._save_config()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            # Continue with defaults
            self._save_config()

    def __repr__(self) -> str:
        """String representation"""
        return f"ModeManager(mode={self.current_mode.value}, session={self.dataset_config.session_name})"


# Global singleton instance
_mode_manager_instance: Optional[ModeManager] = None


def get_mode_manager(config_dir: str = "config") -> ModeManager:
    """
    Get or create global ModeManager instance
    
    Args:
        config_dir: Configuration directory
        
    Returns:
        ModeManager instance
    """
    global _mode_manager_instance
    if _mode_manager_instance is None:
        _mode_manager_instance = ModeManager(config_dir)
    return _mode_manager_instance
