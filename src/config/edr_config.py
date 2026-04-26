"""
Centralized Configuration Management for RDNXSYS EDR

Provides a single source of truth for all tunable parameters across all stages.
Supports environment-based configuration and runtime updates.
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, field

logger = logging.getLogger("edr_config")


@dataclass
class Stage2Config:
    """Stage 2 Prefilter Configuration"""
    # Entropy thresholds
    entropy_threshold: float = 7.9
    entropy_velocity_threshold: float = 0.8
    
    # File operation thresholds
    write_burst_threshold: float = 10.0  # writes per second
    files_modified_threshold: int = 25
    file_delete_burst_threshold: int = 10
    
    # Extension/directory thresholds
    extension_diversity_threshold: int = 8
    dir_file_threshold: int = 50
    
    # Time windows
    window_sec: int = 30
    cleanup_sec: int = 300
    
    # Promotion threshold
    score_promote_threshold: float = 10.0
    
    # Honeypot paths
    honey_dirs: list = field(default_factory=lambda: [r"C:\Honeypots"])
    honey_files: set = field(default_factory=lambda: {"budget.xlsx", "passwords.doc", "backup.zip"})
    
    # Enhanced ransomware detection scores
    ransom_note_score: float = 5.0
    mass_file_op_score: float = 3.0
    registry_persistence_score: float = 4.0
    suspicious_domain_score: float = 6.0
    rapid_extension_change_score: float = 4.0


@dataclass
class Stage3Config:
    """Stage 3 Feature Extraction & ML Configuration"""
    # Feature extraction
    feature_window_sec: int = 300  # 5 minutes
    cleanup_sec: int = 600  # 10 minutes
    
    # ML scoring
    ml_threshold: float = 50.0
    ml_model_path: Optional[str] = None
    
    # YARA
    yara_rules_path: Optional[str] = None
    
    # Tier thresholds (0-100 scale)
    tier_low_max: float = 59.0
    tier_medium_max: float = 79.0
    tier_high_max: float = 94.0
    high_band_split_score: float = 87.0  # 80-87 high_low, 88-94 high_high
    # 95-100 = critical
    
    # Feature validation
    min_feature_coverage: float = 0.5  # At least 50% of features must be populated
    min_events_for_scoring: int = 3  # Minimum events needed for reliable scoring


@dataclass
class Stage4Config:
    """Stage 4 Full Scorer Configuration"""
    # Model paths
    tabnet_model_path: Optional[str] = None
    ensemble_model_path: Optional[str] = None
    
    # Decision thresholds
    malicious_threshold: float = 0.7
    suspicious_threshold: float = 0.4

    # Verdict caching
    enable_verdict_cache: bool = True
    verdict_cache_ttl_sec: int = 300
    verdict_cache_max_size: int = 5000


@dataclass
class SystemConfig:
    """System-wide Configuration"""
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Performance
    max_processes_tracked: int = 10000
    cleanup_interval_sec: int = 60
    
    # Dashboard
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8000
    
    # NxLog
    nxlog_config_path: Optional[str] = None
    nxlog_listener_host: str = "127.0.0.1"
    nxlog_listener_port: int = 5050
    
    # Sysmon fallback
    enable_sysmon_fallback: bool = True
    sysmon_bookmark_path: Optional[str] = None


@dataclass
class EDRConfig:
    """Main EDR Configuration Container"""
    stage2: Stage2Config = field(default_factory=Stage2Config)
    stage3: Stage3Config = field(default_factory=Stage3Config)
    stage4: Stage4Config = field(default_factory=Stage4Config)
    system: SystemConfig = field(default_factory=SystemConfig)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EDRConfig':
        """Load configuration from dictionary"""
        return cls(
            stage2=Stage2Config(**data.get("stage2", {})),
            stage3=Stage3Config(**data.get("stage3", {})),
            stage4=Stage4Config(**data.get("stage4", {})),
            system=SystemConfig(**data.get("system", {}))
        )
    
    @classmethod
    def from_file(cls, config_path: str) -> 'EDRConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}, using defaults")
            return cls()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "stage2": asdict(self.stage2),
            "stage3": asdict(self.stage3),
            "stage4": asdict(self.stage4),
            "system": asdict(self.system)
        }
    
    def save_to_file(self, config_path: str) -> None:
        """Save configuration to JSON file"""
        os.makedirs(os.path.dirname(config_path) if os.path.dirname(config_path) else '.', exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    def update_from_dict(self, updates: Dict[str, Any]) -> None:
        """Update configuration from partial dictionary"""
        if "stage2" in updates:
            for key, value in updates["stage2"].items():
                if hasattr(self.stage2, key):
                    setattr(self.stage2, key, value)
        
        if "stage3" in updates:
            for key, value in updates["stage3"].items():
                if hasattr(self.stage3, key):
                    setattr(self.stage3, key, value)
        
        if "stage4" in updates:
            for key, value in updates["stage4"].items():
                if hasattr(self.stage4, key):
                    setattr(self.stage4, key, value)
        
        if "system" in updates:
            for key, value in updates["system"].items():
                if hasattr(self.system, key):
                    setattr(self.system, key, value)


# Global configuration instance
_config: Optional[EDRConfig] = None


def load_config(config_path: Optional[str] = None) -> EDRConfig:
    """Load configuration from file or use defaults"""
    global _config
    
    if config_path is None:
        # Try common config locations
        possible_paths = [
            "config/edr_config.json",
            "edr_config.json",
            os.path.expanduser("~/.rdnxsys/edr_config.json"),
        ]
        config_path = None
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break
    
    if config_path and os.path.exists(config_path):
        _config = EDRConfig.from_file(config_path)
        logger.info(f"Loaded configuration from {config_path}")
    else:
        _config = EDRConfig()
        logger.info("Using default configuration")
        # Save default config for reference
        if config_path:
            _config.save_to_file(config_path)
            logger.info(f"Created default configuration at {config_path}")
    
    return _config


def get_config() -> EDRConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def update_config(updates: Dict[str, Any]) -> None:
    """Update global configuration"""
    global _config
    if _config is None:
        _config = load_config()
    _config.update_from_dict(updates)
    logger.info("Configuration updated")

