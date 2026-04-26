"""
Dataset Collection Initialization Script

Initializes the dataset collection environment and sets up necessary directory structures.
"""

import os
import sys
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_dataset_directories():
    """Create directory structure for dataset collection"""
    base_dirs = [
        'data/dataset_sessions',
        'config',
        'src/dataset_collection'
    ]
    
    for dir_path in base_dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Created/verified directory: {dir_path}")


def create_sample_label_template():
    """Create sample label template for annotation"""
    template = {
        "threat_types": [
            "benign",
            "ransomware",
            "trojan",
            "lateral_movement",
            "privilege_escalation",
            "data_exfiltration",
            "c2_communication",
            "suspicious"
        ],
        "common_tags": [
            "encryption",
            "file-access",
            "registry-modify",
            "network-connect",
            "process-create",
            "process-inject",
            "dll-load",
            "lateral-move",
            "c2",
            "persistence",
            "reconnaissance"
        ],
        "ransomware_indicators": [
            "file-encryption",
            "shadow-copy-deletion",
            "ransom-note-creation",
            "mass-file-modification",
            "rapid-extension-change",
            "registry-modification",
            "c2-communication"
        ]
    }
    
    import json
    template_file = Path('data/label_templates/default.json')
    template_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(template_file, 'w') as f:
        json.dump(template, f, indent=2)
    
    logger.info(f"✓ Created label template: {template_file}")


def verify_imports():
    """Verify required imports are available"""
    required_modules = [
        'src.config.mode_config',
        'src.dataset_collection.collection_engine',
        'src.dataset_collection.annotation_manager'
    ]
    
    logger.info("\nVerifying imports...")
    for module in required_modules:
        try:
            __import__(module)
            logger.info(f"✓ {module}")
        except ImportError as e:
            logger.error(f"✗ {module}: {e}")
            return False
    
    return True


def initialize_config():
    """Initialize configuration files"""
    try:
        from src.config.mode_config import get_mode_manager, RunMode
        
        manager = get_mode_manager()
        logger.info(f"✓ Mode manager initialized: {manager.current_mode.value}")
        logger.info(f"✓ Configuration saved to: {manager.config_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize config: {e}")
        return False


def main():
    """Run initialization"""
    logger.info("=" * 60)
    logger.info("Dataset Collection System Initialization")
    logger.info("=" * 60)
    
    try:
        # Create directories
        logger.info("\n[1/4] Creating directories...")
        create_dataset_directories()
        
        # Create templates
        logger.info("\n[2/4] Creating label templates...")
        create_sample_label_template()
        
        # Verify imports
        logger.info("\n[3/4] Verifying imports...")
        if not verify_imports():
            logger.error("Import verification failed")
            return False
        
        # Initialize config
        logger.info("\n[4/4] Initializing configuration...")
        if not initialize_config():
            logger.error("Configuration initialization failed")
            return False
        
        logger.info("\n" + "=" * 60)
        logger.info("✓ Initialization completed successfully!")
        logger.info("=" * 60)
        logger.info("\nYou can now start dataset collection with:")
        logger.info("  python src/unified_launcher.py --dataset-mode --session-name 'your_session'")
        logger.info("\nOr run in production mode with:")
        logger.info("  python src/unified_launcher.py --stage3-model-path models/stage3_balanced_v2")
        
        return True
    except Exception as e:
        logger.error(f"\n✗ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
