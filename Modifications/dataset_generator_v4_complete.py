#!/usr/bin/env python3
"""
Complete EDR Dataset Generator v4 - All-in-one with adversarial/evasion capabilities.

This is a CONSOLIDATED version combining:
- Base dataset_generator.py (realistic lifecycle, process trees, temporal dynamics)
- V4 enhancements (adversarial mutations, kill chain, network, persistence, labels)
- Integrated pipeline (seamless feature mixing)

SINGLE FILE - NO IMPORTS NEEDED (except numpy, pandas, pyarrow)

Usage:
  # Standard generation (original behavior)
    python dataset_generator_v4_complete.py --rows 5000 --seed 42
  
  # Adversarial samples (80% evasion)
    python dataset_generator_v4_complete.py --rows 1000 --enable-adversarial --adversarial-ratio 0.8
  
    # Full v4 (all features)
    python dataset_generator_v4_complete.py --rows 5000 --enable-all-v4 --seed 42
  
  # Multi-stage attack detection
    python dataset_generator_v4_complete.py --rows 5000 --enable-attack-chain --enable-multidim-labels

This script is self-contained and requires only: numpy, pandas, pyarrow
"""

import argparse
import hashlib
import json
import random
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# ========================================================================================
# SECTION 1: BASE SCHEMA (from dataset_generator.py)
# ========================================================================================

EXPECTED_FEATURES: List[str] = [
    'cpu_usage_trend', 'cpu_spike_deviation', 'ram_usage_trend', 'sudden_ram_spikes',
    'thread_count_delta', 'handle_count_delta',
    'total_bytes_written', 'files_created', 'files_modified', 'files_deleted',
    'files_created_rate', 'files_deleted_rate', 'bytes_written_rate',
    'lifecycle_peak_file_rate', 'burstiness_file_io', 'medium_term_file_rate',
    'long_term_file_rate', 'file_io_acceleration',
    'entropy_trend', 'entropy_velocity', 'entropy_acceleration',
    'signature_trust_level', 'is_microsoft_signed', 'cert_mismatch_tampering',
    'parent_child_anomaly_score', 'unexpected_spawning_patterns',
    'spawn_depth', 'injection_edge_flag', 'shared_handles_flag',
    'family_file_creates', 'family_file_deletes', 'family_network_conns',
    'family_registry_mods', 'sibling_count', 'family_entropy_avg',
    'family_suspicious_paths', 'family_file_rate', 'family_network_rate',
    'network_connections', 'dns_lookup_count', 'outbound_connection_anomaly',
    'total_sockets_created', 'unexpected_ports_touched', 'unusual_destination_ip_behavior',
    'network_connection_rate', 'network_burst_60s',
    'beacon_interval_std', 'suspicious_tld_flag', 'asn_risk_score', 'geo_risk_score',
    'working_directory_anomaly', 'executable_path_mismatch',
    'image_memory_disk_mismatch', 'unsigned_image_mapped', 'writexecutable_memory_regions',
    'memory_region_entropy_anomalies', 'thread_start_address_anomalies',
    'module_load_anomaly_score', 'unexpected_dlls_loaded', 'dlls_unusual_directories',
    'suspicious_api_call_frequency', 'excessive_crypt_apis', 'excessive_virtualalloc',
    'excessive_writeprocessmemory', 'excessive_createremotethread',
    'token_privilege_escalation', 'unexpected_privilege_acquisition', 'access_token_manipulation',
    'registry_modification_anomaly', 'scheduled_task_creation_attempts',
    'process_created_suspended', 'ntunmapviewofsection_usage', 'large_writeprocessmemory_activity',
    'thread_resume_sequence_anomalies',
    'file_rename_patterns', 'file_extension_anomaly', 'content_rewriting_patterns',
    'suspicious_honeypot_access',
    'user_interactivity_anomaly', 'unexpected_gui_access', 'unexpected_clipboard_access',
    'temporal_correlation_spikes', 'temporal_spikes_5min', 'temporal_spikes_30min',
    'file_event_concentration', 'baseline_deviation_score',
    'yara_match_memory', 'yara_match_executable', 'yara_match_script',
    'yara_match_document', 'yara_match_ads', 'yara_weighted_confidence',
    'yara_match_strength',
]

RANSOMWARE_CRITICAL = {
    'entropy_trend', 'entropy_velocity', 'burstiness_file_io', 'files_modified',
    'files_deleted', 'total_bytes_written', 'excessive_crypt_apis', 'content_rewriting_patterns',
    'file_extension_anomaly', 'file_rename_patterns', 'registry_modification_anomaly',
    'scheduled_task_creation_attempts', 'unexpected_spawning_patterns', 'parent_child_anomaly_score',
    'working_directory_anomaly', 'executable_path_mismatch', 'spawn_depth', 'injection_edge_flag',
    'beacon_interval_std', 'suspicious_tld_flag'
}

SCHEMA_VERSION = "realistic_v4"
FEATURE_LIST_HASH = hashlib.sha256("|".join(EXPECTED_FEATURES).encode("utf-8")).hexdigest()
SNAPSHOT_PHASES = [0.2, 0.4, 0.6, 0.8, 1.0]


def _derive_stage3_score_and_tier(features: Dict[str, float]) -> Tuple[float, str]:
    """Derive Stage 3 telemetry from behavior-only features (no label shortcuts)."""
    weights = {
        'entropy_trend': 0.11,
        'entropy_velocity': 0.08,
        'files_modified': 0.10,
        'files_deleted': 0.06,
        'total_bytes_written': 0.08,
        'excessive_crypt_apis': 0.12,
        'file_rename_patterns': 0.10,
        'file_extension_anomaly': 0.10,
        'content_rewriting_patterns': 0.08,
        'network_burst_60s': 0.07,
        'writexecutable_memory_regions': 0.06,
        'yara_weighted_confidence': 0.04,
    }

    def _norm(name: str, raw: float) -> float:
        if name == 'entropy_trend':
            return _bounded((raw - 4.0) / 4.5, 0.0, 1.0)
        if name == 'entropy_velocity':
            return _bounded((raw + 1.0) / 2.2, 0.0, 1.0)
        if name in {'files_modified', 'files_deleted'}:
            return _bounded(raw / 250.0, 0.0, 1.0)
        if name == 'total_bytes_written':
            return _bounded(raw / float(1_200_000_000), 0.0, 1.0)
        if name == 'excessive_crypt_apis':
            return _bounded(raw / 16.0, 0.0, 1.0)
        if name in {'file_rename_patterns', 'file_extension_anomaly', 'content_rewriting_patterns'}:
            return _bounded(raw / 15.0, 0.0, 1.0)
        if name == 'network_burst_60s':
            return _bounded(raw / 40.0, 0.0, 1.0)
        if name in {'writexecutable_memory_regions', 'yara_weighted_confidence'}:
            return _bounded(raw, 0.0, 1.0)
        return _bounded(raw, 0.0, 1.0)

    weighted = 0.0
    for feat, weight in weights.items():
        weighted += weight * _norm(feat, float(features.get(feat, 0.0) or 0.0))

    score = _bounded(weighted * 100.0, 0.0, 100.0)
    if score < 60.0:
        tier = 'low'
    elif score < 80.0:
        tier = 'medium'
    elif score < 95.0:
        tier = 'high'
    else:
        tier = 'critical'
    return score, tier

HOSTS = [
    ("WORKSTATION-001", "DOMAIN\\alice"),
    ("LAPTOP-002", "LOCAL\\bob"),
    ("SERVER-003", "SYSTEM"),
    ("DESKTOP-004", "DOMAIN\\charlie"),
    ("WORKSTATION-005", "LOCAL\\dave"),
]

LEGIT_BINARIES = [
    r"C:\\Windows\\System32\\svchost.exe",
    r"C:\\Windows\\System32\\explorer.exe",
    r"C:\\Windows\\System32\\powershell.exe",
    r"C:\\Windows\\System32\\cmd.exe",
    r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    r"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    r"C:\\Windows\\System32\\msiexec.exe",
    r"C:\\Windows\\System32\\rundll32.exe",
    r"C:\\Windows\\System32\\wscript.exe",
]

MASQ_BINARIES = [
    r"C:\\Users\\{user}\\AppData\\Local\\Temp\\svchost.exe",
    r"C:\\Users\\{user}\\Downloads\\update_{n}.exe",
    r"C:\\Windows\\Temp\\service_{n}.exe",
]

BENIGN_PERSONAS = {
    'backup': {
        'roots': [r"C:\\Program Files\\Backup\\agent.exe", r"C:\\Windows\\System32\\wbadmin.exe"],
        'children': [r"C:\\Windows\\System32\\vssadmin.exe", r"C:\\Windows\\System32\\robocopy.exe"],
        'high_entropy': True, 'high_file_io': True, 'crypto_allowed': True,
    },
    'installer': {
        'roots': [r"C:\\Windows\\System32\\msiexec.exe", r"C:\\Users\\{user}\\Downloads\\setup.exe"],
        'children': [r"C:\\Windows\\System32\\cmd.exe", r"C:\\Windows\\System32\\powershell.exe"],
        'high_entropy': False, 'high_file_io': True, 'crypto_allowed': False,
    },
    'av_scan': {
        'roots': [r"C:\\Program Files\\Windows Defender\\MsMpEng.exe"],
        'children': [r"C:\\Windows\\System32\\cmd.exe"],
        'high_entropy': True, 'high_file_io': True, 'crypto_allowed': True,
    },
    'compression': {
        'roots': [r"C:\\Program Files\\7-Zip\\7z.exe", r"C:\\Windows\\System32\\compact.exe"],
        'children': [],
        'high_entropy': True, 'high_file_io': True, 'crypto_allowed': False,
    },
}

RANSOM_TREE_TEMPLATES = [
    {
        'root': r"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        'children': [r"C:\\Windows\\System32\\powershell.exe", r"C:\\Windows\\System32\\cmd.exe"],
        'unusual': True,
    },
    {
        'root': r"C:\\Windows\\System32\\explorer.exe",
        'children': [r"C:\\Users\\{user}\\Downloads\\update_{n}.exe", r"C:\\Windows\\System32\\wscript.exe"],
        'unusual': True,
    },
    {
        'root': r"C:\\Windows\\System32\\services.exe",
        'children': [r"C:\\Windows\\Temp\\service_{n}.exe"],
        'unusual': False,
    },
]

# ========================================================================================
# SECTION 2: KNOBS & CONFIG
# ========================================================================================

@dataclass
class Knobs:
    benign_ratio: float = 0.8  # Changed to 80/20 ratio (80% benign, 20% malicious)
    p_benign_hits_ransom_signals: float = 0.50  # INCREASED: Force more benign overlap (was 0.20)
    p_ransom_skips_obvious: float = 0.4  # INCREASED: More malicious evasion (was 0.3)
    p_noise_missing: float = 0.05
    p_noise_duplicate: float = 0.03
    p_out_of_order: float = 0.05
    p_path_masquerade: float = 0.15
    p_low_entropy: float = 0.2
    p_lolbin_heavy: float = 0.25
    p_partial_failure: float = 0.25
    p_burst_trigger: float = 0.15
    burst_decay_rate: float = 0.6
    min_tree_size: int = 3
    max_tree_size: int = 12
    p_benign_backup: float = 0.15
    p_benign_installer: float = 0.15
    p_benign_av_scan: float = 0.10
    p_benign_compression: float = 0.10
    target_rows: int = 5000
    # V3 additions
    enable_adversarial: bool = False
    enable_attack_chain: bool = False
    enable_advanced_network: bool = False
    enable_persistence: bool = False
    enable_multidim_labels: bool = False
    adversarial_ratio: float = 0.2
    adversarial_techniques: List[str] = field(default_factory=lambda: ['fgsm', 'mimicry_backup', 'mimicry_compression', 'causality_preserving'])


# ========================================================================================
# SECTION 3: V3 ADVERSARIAL ENGINE
# ========================================================================================

@dataclass
class AdversarialConfig:
    enable_ml_evasion: bool = False
    enable_mimicry: bool = False
    enable_causality_preserving: bool = False
    epsilon: float = 0.1
    pgd_steps: int = 10
    pgd_step_size: float = 0.01
    mimicry_target: str = 'backup_software'
    mimicry_fidelity: float = 0.85
    critical_features: List[str] = field(default_factory=lambda: [
        'entropy_trend', 'cpu_spike_deviation', 'parent_child_anomaly_score',
        'excessive_crypt_apis', 'file_rename_patterns', 'beacon_interval_std'
    ])


class AdversarialMutationEngine:
    """Apply ML-aware adversarial perturbations."""
    
    def __init__(self, config: AdversarialConfig):
        self.config = config
        self.benign_profiles = {
            'backup_software': {
                'entropy_trend': (5.5, 6.5), 'cpu_usage_trend': (40, 60),
                'excessive_crypt_apis': (3, 8), 'files_modified': (50, 150),
                'parent_child_anomaly_score': (0.1, 0.3),
            },
            'compression_tool': {
                'entropy_trend': (6.0, 7.0), 'cpu_usage_trend': (60, 80),
                'excessive_crypt_apis': (0, 2), 'files_modified': (10, 50),
                'parent_child_anomaly_score': (0.05, 0.2),
            },
            'av_scanner': {
                'entropy_trend': (5.8, 6.8), 'cpu_usage_trend': (50, 70),
                'excessive_crypt_apis': (2, 6), 'files_modified': (30, 100),
                'parent_child_anomaly_score': (0.1, 0.25),
            },
        }
    
    def apply_evasion(self, features: Dict[str, float], label: int, technique: str = 'fgsm') -> Dict[str, float]:
        if label == 0 or not self.config.enable_ml_evasion:
            return features
        
        if technique == 'fgsm':
            return self._fgsm_perturbation(features)
        elif technique.startswith('mimicry_'):
            target = technique.split('_')[1]
            return self._mimicry_attack(features, target)
        elif technique == 'causality_preserving':
            return self._causality_preserving_evasion(features)
        return features
    
    def _fgsm_perturbation(self, features: Dict[str, float]) -> Dict[str, float]:
        perturbed = features.copy()
        for feat in self.config.critical_features:
            if feat in perturbed:
                sign = random.choice([-1, 1])
                perturbed[feat] += sign * self.config.epsilon * abs(perturbed[feat])
                perturbed[feat] = max(0, perturbed[feat])
        return perturbed
    
    def _mimicry_attack(self, features: Dict[str, float], target_profile: str) -> Dict[str, float]:
        if target_profile not in self.benign_profiles:
            return features
        profile = self.benign_profiles[target_profile]
        perturbed = features.copy()
        for feat, (low, high) in profile.items():
            if feat in perturbed:
                target_val = (low + high) / 2.0
                perturbed[feat] = (
                    self.config.mimicry_fidelity * target_val +
                    (1 - self.config.mimicry_fidelity) * perturbed[feat]
                )
        return perturbed
    
    def _causality_preserving_evasion(self, features: Dict[str, float]) -> Dict[str, float]:
        perturbed = features.copy()
        if perturbed.get('entropy_trend', 0) > 7.0 and perturbed.get('file_rename_patterns', 0) > 5.0:
            scale = 0.8
            perturbed['entropy_trend'] *= scale
            perturbed['file_rename_patterns'] *= scale
        if perturbed.get('excessive_crypt_apis', 0) > 8 and perturbed.get('cpu_spike_deviation', 0) > 30:
            scale = 0.75
            perturbed['excessive_crypt_apis'] *= scale
            perturbed['cpu_spike_deviation'] *= scale
        if perturbed.get('parent_child_anomaly_score', 0) > 0.7:
            perturbed['parent_child_anomaly_score'] *= 0.6
        return perturbed


# ========================================================================================
# SECTION 4: V3 ATTACK LIFECYCLE
# ========================================================================================

@dataclass
class AttackStage:
    name: str
    mitre_tactics: List[str]
    techniques: List[Dict[str, str]]
    duration: float
    artifacts: List[str]
    network_activity: bool
    file_activity: bool
    process_activity: bool


class AttackLifecycleSimulator:
    """Simulate full MITRE ATT&CK kill chain."""
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self._define_stages()
    
    def _define_stages(self):
        self.stages = {
            'initial_access': AttackStage(
                name='Initial Access', mitre_tactics=['TA0001'],
                techniques=[
                    {'id': 'T1566.001', 'name': 'Phishing: Spearphishing Attachment'},
                    {'id': 'T1190', 'name': 'Exploit Public-Facing Application'},
                    {'id': 'T1133', 'name': 'External Remote Services (RDP)'},
                ],
                duration=random.uniform(5, 30), artifacts=['email_headers', 'lnk_files', 'macro_docs', 'rdp_logs'],
                network_activity=True, file_activity=True, process_activity=False,
            ),
            'execution': AttackStage(
                name='Execution', mitre_tactics=['TA0002'],
                techniques=[
                    {'id': 'T1059.001', 'name': 'Command and Scripting: PowerShell'},
                    {'id': 'T1059.003', 'name': 'Command and Scripting: Windows Command Shell'},
                    {'id': 'T1204.002', 'name': 'User Execution: Malicious File'},
                ],
                duration=random.uniform(10, 60), artifacts=['powershell_logs', 'cmd_history', 'dropped_executables'],
                network_activity=False, file_activity=True, process_activity=True,
            ),
            'persistence': AttackStage(
                name='Persistence', mitre_tactics=['TA0003'],
                techniques=[
                    {'id': 'T1547.001', 'name': 'Boot or Logon: Registry Run Keys'},
                    {'id': 'T1053.005', 'name': 'Scheduled Task/Job: Scheduled Task'},
                    {'id': 'T1543.003', 'name': 'Create or Modify System Process: Windows Service'},
                ],
                duration=random.uniform(5, 20), artifacts=['registry_keys', 'scheduled_tasks', 'new_services'],
                network_activity=False, file_activity=False, process_activity=True,
            ),
            'defense_evasion': AttackStage(
                name='Defense Evasion', mitre_tactics=['TA0005'],
                techniques=[
                    {'id': 'T1027', 'name': 'Obfuscated Files or Information'},
                    {'id': 'T1070.004', 'name': 'Indicator Removal: File Deletion'},
                    {'id': 'T1562.001', 'name': 'Impair Defenses: Disable or Modify Tools'},
                ],
                duration=random.uniform(10, 40), artifacts=['deleted_logs', 'disabled_av', 'obfuscated_scripts'],
                network_activity=False, file_activity=True, process_activity=True,
            ),
            'credential_access': AttackStage(
                name='Credential Access', mitre_tactics=['TA0006'],
                techniques=[
                    {'id': 'T1003.001', 'name': 'OS Credential Dumping: LSASS Memory'},
                    {'id': 'T1003.002', 'name': 'OS Credential Dumping: Security Account Manager'},
                ],
                duration=random.uniform(5, 15), artifacts=['lsass_dump', 'sam_hive_copy', 'mimikatz_artifacts'],
                network_activity=False, file_activity=True, process_activity=True,
            ),
            'discovery': AttackStage(
                name='Discovery', mitre_tactics=['TA0007'],
                techniques=[
                    {'id': 'T1083', 'name': 'File and Directory Discovery'},
                    {'id': 'T1018', 'name': 'Remote System Discovery'},
                    {'id': 'T1082', 'name': 'System Information Discovery'},
                ],
                duration=random.uniform(20, 120), artifacts=['net_view_commands', 'dir_listings', 'systeminfo_output'],
                network_activity=True, file_activity=False, process_activity=True,
            ),
            'lateral_movement': AttackStage(
                name='Lateral Movement', mitre_tactics=['TA0008'],
                techniques=[
                    {'id': 'T1021.002', 'name': 'Remote Services: SMB/Windows Admin Shares'},
                    {'id': 'T1047', 'name': 'Windows Management Instrumentation'},
                    {'id': 'T1570', 'name': 'Lateral Tool Transfer'},
                ],
                duration=random.uniform(30, 180), artifacts=['psexec_logs', 'wmi_events', 'smb_connections'],
                network_activity=True, file_activity=True, process_activity=True,
            ),
            'collection': AttackStage(
                name='Collection', mitre_tactics=['TA0009'],
                techniques=[
                    {'id': 'T1560.001', 'name': 'Archive Collected Data: Archive via Utility'},
                    {'id': 'T1005', 'name': 'Data from Local System'},
                ],
                duration=random.uniform(60, 300), artifacts=['7z_archives', 'rar_files', 'staged_directories'],
                network_activity=False, file_activity=True, process_activity=True,
            ),
            'exfiltration': AttackStage(
                name='Exfiltration', mitre_tactics=['TA0010'],
                techniques=[
                    {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel'},
                    {'id': 'T1048.003', 'name': 'Exfiltration Over Alternative Protocol'},
                    {'id': 'T1567.002', 'name': 'Exfiltration Over Web Service: Cloud Storage'},
                ],
                duration=random.uniform(120, 600), artifacts=['dns_queries', 'https_posts', 'cloud_api_calls'],
                network_activity=True, file_activity=False, process_activity=False,
            ),
            'impact': AttackStage(
                name='Impact', mitre_tactics=['TA0040'],
                techniques=[
                    {'id': 'T1486', 'name': 'Data Encrypted for Impact'},
                    {'id': 'T1490', 'name': 'Inhibit System Recovery'},
                    {'id': 'T1491', 'name': 'Defacement'},
                ],
                duration=random.uniform(60, 600), artifacts=['encrypted_files', 'ransom_notes', 'shadow_copy_deletion'],
                network_activity=True, file_activity=True, process_activity=True,
            ),
        }
    
    def generate_attack_chain(self, label: int, family: str = 'generic') -> List[Dict]:
        if label == 0:
            return []
        chain = []
        cumulative_time = 0.0
        stage_order = [
            'initial_access', 'execution', 'persistence', 'defense_evasion',
            'credential_access' if random.random() < 0.6 else None,
            'discovery', 'lateral_movement' if random.random() < 0.4 else None,
            'collection' if random.random() < 0.7 else None,
            'exfiltration' if random.random() < 0.5 else None,
            'impact',
        ]
        for stage_name in stage_order:
            if stage_name is None:
                continue
            stage = self.stages[stage_name]
            chain.append({
                'stage': stage.name,
                'mitre_tactics': stage.mitre_tactics,
                'techniques': random.sample(stage.techniques, k=min(2, len(stage.techniques))),
                'start_time': cumulative_time,
                'duration': stage.duration,
                'end_time': cumulative_time + stage.duration,
                'artifacts': stage.artifacts,
                'network_activity': stage.network_activity,
                'file_activity': stage.file_activity,
                'process_activity': stage.process_activity,
            })
            cumulative_time += stage.duration
        return chain


# ========================================================================================
# SECTION 5: V3 NETWORK SIMULATOR
# ========================================================================================

class AdvancedNetworkSimulator:
    """Generate realistic network traffic patterns."""
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.c2_infra = {
            'bulletproof_hosting': {
                'countries': ['RU', 'UA', 'NL', 'LV'],
                'asn_risk': (0.7, 0.95),
                'geo_risk': (0.6, 0.9),
            },
            'cloud_providers': {
                'providers': ['AWS', 'Azure', 'GCP', 'DigitalOcean'],
                'regions': ['us-east-1', 'eu-central-1', 'ap-southeast-1'],
                'asn_risk': (0.3, 0.6),
                'geo_risk': (0.2, 0.5),
            },
            'compromised_sites': {
                'types': ['wordpress_blog', 'small_business', 'personal_site'],
                'asn_risk': (0.4, 0.7),
                'geo_risk': (0.3, 0.6),
            },
        }
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'curl/7.81.0',
            'python-requests/2.28.1',
            'Go-http-client/1.1',
        ]
    
    def generate_c2_profile(self, protocol: str = 'https') -> Dict:
        if protocol == 'https':
            return self._https_c2_profile()
        elif protocol == 'dns':
            return self._dns_c2_profile()
        elif protocol == 'icmp':
            return self._icmp_c2_profile()
        return self._https_c2_profile()
    
    def _https_c2_profile(self) -> Dict:
        infra_type = random.choice(['bulletproof_hosting', 'cloud_providers', 'compromised_sites'])
        infra = self.c2_infra[infra_type]
        return {
            'protocol': 'HTTPS',
            'user_agent': random.choice(self.user_agents),
            'beacon_interval_mean': random.uniform(30, 300),
            'beacon_interval_std': random.uniform(0.05, 0.15),
            'request_size_bytes': random.randint(100, 500),
            'response_size_bytes': random.randint(50, 200),
            'encryption': random.choice(['TLS_1.2', 'TLS_1.3']),
            'infra_type': infra_type,
            'asn_risk_score': random.uniform(*infra['asn_risk']),
            'geo_risk_score': random.uniform(*infra['geo_risk']),
            'suspicious_tld': random.random() < 0.35,
        }
    
    def _dns_c2_profile(self) -> Dict:
        return {
            'protocol': 'DNS',
            'query_types': random.sample(['A', 'AAAA', 'TXT', 'MX'], k=2),
            'subdomain_encoding': random.choice(['base32', 'base64', 'hex']),
            'queries_per_minute': random.uniform(2, 10),
            'response_exfiltration': True,
            'beacon_interval_std': random.uniform(0.1, 0.3),
            'asn_risk_score': random.uniform(0.4, 0.8),
            'geo_risk_score': random.uniform(0.3, 0.7),
        }
    
    def _icmp_c2_profile(self) -> Dict:
        return {
            'protocol': 'ICMP',
            'packet_size': random.randint(64, 512),
            'packets_per_minute': random.uniform(5, 20),
            'encoding': 'payload_in_data_field',
            'beacon_interval_std': random.uniform(0.2, 0.5),
            'asn_risk_score': random.uniform(0.5, 0.85),
            'geo_risk_score': random.uniform(0.4, 0.75),
        }
    
    def generate_exfiltration_pattern(self, method: str = 'https') -> Dict:
        patterns = {
            'slow_drip': {
                'volume_per_hour_mb': random.uniform(1, 10),
                'duration_hours': random.uniform(24, 168),
                'timing': 'business_hours',
            },
            'burst_exfil': {
                'volume_per_hour_mb': random.uniform(100, 1000),
                'duration_hours': random.uniform(0.5, 4),
                'timing': 'off_hours',
            },
            'continuous_stream': {
                'volume_per_hour_mb': random.uniform(20, 100),
                'duration_hours': random.uniform(4, 72),
                'timing': 'continuous',
            },
        }
        pattern_type = random.choice(list(patterns.keys()))
        pattern = patterns[pattern_type]
        pattern['method'] = method
        pattern['encryption'] = 'double_encrypted' if random.random() < 0.3 else 'single_layer'
        return pattern


# ========================================================================================
# SECTION 6: V3 PERSISTENCE GENERATOR
# ========================================================================================

class PersistenceMechanismGenerator:
    """Generate diverse persistence mechanisms."""
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
    
    def generate_persistence_set(self, label: int, count: int = 2) -> List[Dict]:
        if label == 0:
            return []
        mechanisms = []
        available = [
            'registry_run_key', 'scheduled_task', 'windows_service',
            'wmi_event_subscription', 'com_hijacking', 'ifeo_debugger',
        ]
        selected = random.sample(available, k=min(count, len(available)))
        for mech_type in selected:
            if mech_type == 'registry_run_key':
                mechanisms.append(self._registry_run_key())
            elif mech_type == 'scheduled_task':
                mechanisms.append(self._scheduled_task())
            elif mech_type == 'windows_service':
                mechanisms.append(self._windows_service())
            elif mech_type == 'wmi_event_subscription':
                mechanisms.append(self._wmi_event_subscription())
            elif mech_type == 'com_hijacking':
                mechanisms.append(self._com_hijacking())
            elif mech_type == 'ifeo_debugger':
                mechanisms.append(self._ifeo_debugger())
        return mechanisms
    
    def _registry_run_key(self) -> Dict:
        locations = [
            r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        ]
        return {
            'type': 'registry_run_key',
            'mitre_technique': 'T1547.001',
            'location': random.choice(locations),
            'value_name': random.choice(['Updater', 'SecurityCenter', 'SystemCheck']),
            'binary_path': r'C:\Users\User\AppData\Local\Temp\svchost.exe',
        }
    
    def _scheduled_task(self) -> Dict:
        triggers = ['logon', 'startup', 'daily', 'idle']
        return {
            'type': 'scheduled_task',
            'mitre_technique': 'T1053.005',
            'task_name': random.choice(['WindowsUpdate', 'SystemMaintenance', 'SecurityScan']),
            'trigger': random.choice(triggers),
            'binary_path': r'C:\Windows\Temp\service.exe',
            'run_level': 'highest',
        }
    
    def _windows_service(self) -> Dict:
        return {
            'type': 'windows_service',
            'mitre_technique': 'T1543.003',
            'service_name': random.choice(['WinDefender', 'SecurityService', 'UpdaterSvc']),
            'display_name': random.choice(['Windows Defender Service', 'Security Update', 'System Updater']),
            'binary_path': r'C:\Windows\System32\malware.exe',
            'start_type': 'automatic',
        }
    
    def _wmi_event_subscription(self) -> Dict:
        return {
            'type': 'wmi_event_subscription',
            'mitre_technique': 'T1546.003',
            'event_filter': 'Win32_ProcessStartTrace',
            'consumer_type': 'CommandLineEventConsumer',
            'command': r'powershell.exe -enc <base64_payload>',
        }
    
    def _com_hijacking(self) -> Dict:
        return {
            'type': 'com_hijacking',
            'mitre_technique': 'T1546.015',
            'clsid': '{BCDE0395-E52F-467C-8E3D-C4579291692E}',
            'hijack_method': 'InprocServer32',
            'malicious_dll': r'C:\Users\User\AppData\Local\Temp\evil.dll',
        }
    
    def _ifeo_debugger(self) -> Dict:
        return {
            'type': 'ifeo_debugger',
            'mitre_technique': 'T1546.012',
            'target_binary': 'sethc.exe',
            'debugger_path': r'C:\Windows\System32\cmd.exe',
            'location': r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        }


# ========================================================================================
# SECTION 7: V3 MULTI-DIMENSIONAL LABELS
# ========================================================================================

@dataclass
class MultiDimensionalLabel:
    """Rich ground truth label with MITRE ATT&CK mapping."""
    pid: int
    binary_label: int
    attack_stage: Optional[str] = None
    techniques: List[Dict[str, str]] = field(default_factory=list)
    ransomware_family: Optional[str] = None
    encryption_type: Optional[str] = None
    persistence_mechanisms: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    detection_difficulty: str = 'medium'
    first_seen_epoch: float = 0.0
    encryption_start_epoch: Optional[float] = None
    ransom_note_dropped_epoch: Optional[float] = None
    c2_checkin_times: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'pid': self.pid,
            'binary_label': self.binary_label,
            'attack_stage': self.attack_stage,
            'techniques': self.techniques,
            'ransomware_family': self.ransomware_family,
            'encryption_type': self.encryption_type,
            'persistence_mechanisms': self.persistence_mechanisms,
            'evasion_techniques': self.evasion_techniques,
            'detection_difficulty': self.detection_difficulty,
            'timeline': {
                'first_seen': self.first_seen_epoch,
                'encryption_start': self.encryption_start_epoch,
                'ransom_note_dropped': self.ransom_note_dropped_epoch,
                'c2_checkins': self.c2_checkin_times,
            }
        }


def generate_multidimensional_label(pid: int, label: int, attack_chain: List[Dict], 
                                     persistence: List[Dict], base_ts: float) -> MultiDimensionalLabel:
    if label == 0:
        return MultiDimensionalLabel(pid=pid, binary_label=0, detection_difficulty='low', first_seen_epoch=base_ts)
    
    attack_stage = attack_chain[-1]['stage'].lower().replace(' ', '_') if attack_chain else 'unknown'
    techniques = []
    for stage in attack_chain:
        for tech in stage['techniques']:
            techniques.append({
                'id': tech['id'],
                'name': tech['name'],
                'confidence': random.uniform(0.8, 0.98),
            })
    
    families = ['conti', 'lockbit', 'blackcat', 'hive', 'royal', 'alphv', 'generic']
    family = random.choice(families)
    encryption_types = ['hybrid_aes_rsa', 'chacha20', 'aes_256_cbc', 'salsa20', 'intermittent_aes']
    encryption_type = random.choice(encryption_types)
    persist_types = [p['type'] for p in persistence]
    evasion = random.sample(['process_hollowing', 'amsi_bypass', 'etw_patching', 'obfuscation', 'reflective_dll', 'mimicry_attack'], k=random.randint(1, 3))
    
    if len(evasion) >= 3:
        difficulty = 'very_high'
    elif len(evasion) >= 2:
        difficulty = 'high'
    elif len(evasion) >= 1:
        difficulty = 'medium'
    else:
        difficulty = 'low'
    
    first_seen = base_ts
    encryption_start = base_ts + sum(s['duration'] for s in attack_chain[:-1]) if attack_chain else base_ts + 100
    ransom_note = encryption_start + random.uniform(10, 60)
    c2_checkins = [base_ts + random.uniform(5, 30), encryption_start - 10, encryption_start + 50]
    
    return MultiDimensionalLabel(
        pid=pid, binary_label=1, attack_stage=attack_stage, techniques=techniques,
        ransomware_family=family, encryption_type=encryption_type,
        persistence_mechanisms=persist_types, evasion_techniques=evasion,
        detection_difficulty=difficulty, first_seen_epoch=first_seen,
        encryption_start_epoch=encryption_start, ransom_note_dropped_epoch=ransom_note,
        c2_checkin_times=c2_checkins,
    )


# ========================================================================================
# SECTION 8: BASE GENERATOR HELPERS
# ========================================================================================

def _rand_path(user: str, masquerade: bool) -> str:
    if masquerade and random.random() < 0.6:
        return random.choice(MASQ_BINARIES).format(user=user.split('\\')[-1], n=random.randint(10, 9999))
    return random.choice(LEGIT_BINARIES)

def _bounded(val: float, low: float, high: float) -> float:
    return max(low, min(high, val))

def _maybe_missing(record: Dict[str, object], key: str, p: float) -> None:
    if random.random() < p:
        record.pop(key, None)

def _generate_cmdline(image: str, label: int) -> str:
    lower = image.lower()
    if 'powershell.exe' in lower:
        if label == 1 and random.random() < 0.6:
            b64_stub = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', k=random.randint(20, 80)))
            return f'{image} -NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64_stub}'
        else:
            flags = random.choice(['-NoLogo', '-NonInteractive', '-WindowStyle Hidden', ''])
            script = random.choice(['Get-Process', 'Get-Service', 'Invoke-WebRequest', 'Get-ChildItem'])
            return f'{image} {flags} -Command "{script}"'
    elif 'cmd.exe' in lower:
        if label == 1 and random.random() < 0.5:
            return f'{image} /c "cd %TEMP% && echo payload > file.txt && del /F /Q *.tmp"'
        else:
            return f'{image} /c {random.choice(["dir", "ipconfig", "tasklist", "whoami"])}'
    elif 'rundll32.exe' in lower:
        dll_name = random.choice(['user32.dll', 'kernel32.dll', 'shell32.dll', 'advapi32.dll'])
        entry = random.choice(['LockWorkStation', 'SetSuspendState', 'Control_RunDLL'])
        return f'{image} {dll_name},{entry}'
    elif 'msiexec.exe' in lower:
        return f'{image} /i setup.msi /quiet /norestart'
    elif 'svchost.exe' in lower:
        group = random.choice(['netsvcs', 'LocalService', 'NetworkService'])
        return f'{image} -k {group}'
    elif 'wscript.exe' in lower or 'cscript.exe' in lower:
        script_ext = random.choice(['.vbs', '.js'])
        return f'{image} //B //Nologo script{script_ext}'
    else:
        return f'{image} {random.choice(["--run", "/start", "-q", ""])}'


# ========================================================================================
# SECTION 9: BURST STATE MACHINE
# ========================================================================================

class BurstState:
    """Tracks burst/spike/decay dynamics."""
    
    def __init__(self, aggressive: bool, decay_rate: float):
        self.state = 'idle'
        self.intensity = 0.0
        self.time_since_spike = 0
        self.aggressive = aggressive
        self.decay_rate = decay_rate
        self.spike_prob = 0.25 if aggressive else 0.12
    
    def update(self, phase_delta: float) -> float:
        if self.state == 'idle':
            if random.random() < self.spike_prob * phase_delta / 0.2:
                self.state = 'spike'
                self.intensity = random.uniform(1.5, 3.0) if self.aggressive else random.uniform(1.2, 2.0)
                self.time_since_spike = 0
                return self.intensity
            return 1.0
        elif self.state == 'spike':
            self.state = 'decay'
            self.time_since_spike += phase_delta
            return self.intensity
        elif self.state == 'decay':
            self.time_since_spike += phase_delta
            decay_factor = self.decay_rate if self.aggressive else (self.decay_rate * 1.5)
            self.intensity *= (1.0 - decay_factor * phase_delta / 0.2)
            if self.intensity < 1.05:
                self.state = 'idle'
                self.intensity = 0.0
            return max(1.0, self.intensity)
        return 1.0


# ========================================================================================
# SECTION 10: CAUSAL STATE
# ========================================================================================

class CausalState:
    """Tracks causal dependencies between features."""
    
    def __init__(self):
        self.scheduled: Dict[str, List[Tuple[float, str, float]]] = {}
    
    def trigger(self, current_phase: float, trigger_name: str, target_feature: str, boost: float, delay: float = 0.2):
        target_phase = current_phase + delay
        if target_phase not in self.scheduled:
            self.scheduled[target_phase] = []
        self.scheduled[target_phase].append((target_feature, boost))
    
    def get_boosts(self, phase: float) -> Dict[str, float]:
        boosts = {}
        for sched_phase in list(self.scheduled.keys()):
            if abs(sched_phase - phase) < 0.05:
                for feat, boost in self.scheduled[sched_phase]:
                    boosts[feat] = boosts.get(feat, 0.0) + boost
                del self.scheduled[sched_phase]
        return boosts


# ========================================================================================
# SECTION 11: PROCESS TREE
# ========================================================================================

@dataclass
class ProcessTreeNode:
    pid: int
    ppid: int
    image: str
    spawn_depth: int
    label: int


class ProcessTree:
    """Manages a process tree with root and children."""
    
    def __init__(self, tree_id: str, label: int, knobs: Knobs, base_ts: float):
        self.tree_id = tree_id
        self.label = label
        self.knobs = knobs
        self.base_ts = base_ts
        self.nodes: List[ProcessTreeNode] = []
        self.persona = None
        if label == 0:
            r = random.random()
            if r < knobs.p_benign_backup:
                self.persona = 'backup'
            elif r < knobs.p_benign_backup + knobs.p_benign_installer:
                self.persona = 'installer'
            elif r < knobs.p_benign_backup + knobs.p_benign_installer + knobs.p_benign_av_scan:
                self.persona = 'av_scan'
            elif r < knobs.p_benign_backup + knobs.p_benign_installer + knobs.p_benign_av_scan + knobs.p_benign_compression:
                self.persona = 'compression'
    
    def build_tree(self, start_pid: int, host: str, user: str) -> List['PIDState']:
        tree_size = random.randint(self.knobs.min_tree_size, self.knobs.max_tree_size)
        states = []
        
        if self.label == 1:
            template = random.choice(RANSOM_TREE_TEMPLATES)
            root_image = template['root'].format(user=user.split('\\')[-1])
            child_templates = template['children']
            unusual_parent = template['unusual']
        else:
            if self.persona and self.persona in BENIGN_PERSONAS:
                persona_data = BENIGN_PERSONAS[self.persona]
                root_image = random.choice(persona_data['roots']).format(user=user.split('\\')[-1])
                child_templates = persona_data['children']
            else:
                root_image = random.choice(LEGIT_BINARIES)
                child_templates = [r"C:\\Windows\\System32\\cmd.exe", r"C:\\Windows\\System32\\conhost.exe"]
            # FIXED: Allow benign samples to sometimes have unusual parents (installers, dev tools)
            # This increases overlap and reduces parent_child_anomaly_score dominance
            if self.persona == 'installer':
                # Installers often spawn from unusual parents (e.g., browser → installer → cmd)
                unusual_parent = random.random() < 0.4  # 40% chance
            elif random.random() < 0.15:
                # 15% of other benign processes can have unusual parents (dev tools, complex apps)
                unusual_parent = True
            else:
                unusual_parent = False
        
        root_node = ProcessTreeNode(start_pid, 0, root_image, 0, self.label)
        self.nodes.append(root_node)
        root_state = PIDState(start_pid, self.label, self.knobs, self.base_ts, 
                              tree_id=self.tree_id, spawn_depth=0, parent_image='', 
                              persona=self.persona, unusual_parent=unusual_parent)
        states.append(root_state)
        
        current_pid = start_pid + 1
        remaining = tree_size - 1
        for i in range(remaining):
            parent = random.choice(self.nodes)
            depth = parent.spawn_depth + 1
            if depth > 5:
                continue
            
            if self.label == 1:
                child_image = random.choice(child_templates).format(user=user.split('\\')[-1], n=random.randint(100, 9999))
            else:
                if self.persona and self.persona in BENIGN_PERSONAS and BENIGN_PERSONAS[self.persona]['children']:
                    child_image = random.choice(BENIGN_PERSONAS[self.persona]['children'])
                else:
                    child_image = random.choice(LEGIT_BINARIES)
            
            child_node = ProcessTreeNode(current_pid, parent.pid, child_image, depth, self.label)
            self.nodes.append(child_node)
            child_state = PIDState(current_pid, self.label, self.knobs, self.base_ts + random.uniform(0, 10),
                                   tree_id=self.tree_id, spawn_depth=depth, parent_image=parent.image,
                                   persona=self.persona, unusual_parent=unusual_parent)
            states.append(child_state)
            current_pid += 1
        
        return states


# ========================================================================================
# SECTION 12: PID STATE
# ========================================================================================

class PIDState:
    """Tracks cumulative, monotonic metrics per PID."""

    def __init__(self, pid: int, label: int, knobs: Knobs, base_ts: float,
                 tree_id: str = '', spawn_depth: int = 0, parent_image: str = '',
                 persona: str = None, unusual_parent: bool = False):
        self.pid = pid
        self.label = label
        self.knobs = knobs
        self.base_ts = base_ts
        self.host, self.user = random.choice(HOSTS)
        
        self.tree_id = tree_id or f'tree_{pid}'
        self.spawn_depth = spawn_depth
        self.parent_image = parent_image if parent_image else ''
        if spawn_depth > 0 and parent_image:
            self.ppid = max(1, pid - random.randint(1, 10))
        else:
            self.ppid = max(1, pid - random.randint(1, 50))
        self.persona = persona
        self.unusual_parent = unusual_parent
        
        if persona and persona in BENIGN_PERSONAS:
            self.image = random.choice(BENIGN_PERSONAS[persona]['roots']).format(user=self.user.split('\\')[-1])
        else:
            self.image = _rand_path(self.user, random.random() < knobs.p_path_masquerade)
        
        self.session_id = random.randint(1, 10)
        self.logon_type = random.choice([2, 3, 5, 10])
        self.is_elevated = (label == 1 and random.random() < 0.4) or (label == 0 and random.random() < 0.1)
        self.uac_bypass = (label == 1 and self.is_elevated and random.random() < 0.3)
        
        self.cumulative = {
            'files_created': 0.0,
            'files_modified': 0.0,
            'files_deleted': 0.0,
            'total_bytes_written': 0.0,
            '_events_seen': 0,
            '_prev_files_per_sec': 0.0,  # For file_io_acceleration
            '_lifecycle_peak_file_rate': 0.0,  # For lifecycle_peak_file_rate
        }
        self.last_phase = 0.0
        self.total_duration = random.uniform(60, 400)
        self.failed = (label == 1 and random.random() < knobs.p_partial_failure)
        self.low_entropy = (label == 1 and random.random() < knobs.p_low_entropy)
        self.lolbin = (label == 1 and random.random() < knobs.p_lolbin_heavy)
        self.overlap = (label == 0 and random.random() < knobs.p_benign_hits_ransom_signals)
        
        self.burst_entropy = BurstState(label == 1 and not self.overlap, knobs.burst_decay_rate)
        self.burst_cpu = BurstState(label == 1 and not self.overlap, knobs.burst_decay_rate)
        self.burst_file_io = BurstState(label == 1 and not self.overlap, knobs.burst_decay_rate)
        
        self.causal = CausalState()
        
        self.has_injection_edge = (label == 1 and random.random() < 0.2)
        self.has_shared_handles = (label == 1 and random.random() < 0.15) or (label == 0 and random.random() < 0.05)
        
        # V3: Evasion & attack chain tracking
        self.adversarial_technique = None
        self.attack_chain = []
        self.c2_profile = {}
        self.persistence_mechanisms = []

    def advance(self, phase: float) -> Tuple[Dict[str, float], Dict[str, object]]:
        if phase < self.last_phase:
            raise ValueError("Phase regression detected")
        phase_delta = phase - self.last_phase
        self.last_phase = phase

        aggressive = self.label == 1 and not self.overlap and not self.failed

        persona_scale = 1.0
        if self.persona:
            persona_data = BENIGN_PERSONAS.get(self.persona, {})
            if persona_data.get('high_file_io'):
                persona_scale = 1.5
        
        burst_file_mult = self.burst_file_io.update(phase_delta)
        burst_cpu_mult = self.burst_cpu.update(phase_delta)
        burst_entropy_mult = self.burst_entropy.update(phase_delta)

        base_fc = 80 if aggressive else 25
        base_fm = 140 if aggressive else 35
        base_fd = 45 if aggressive else 10
        base_bytes = 220 if aggressive else 50
        if self.failed:
            base_fc *= 0.5
            base_fm *= 0.5
            base_fd *= 0.6
            base_bytes *= 0.5
        if self.low_entropy:
            base_bytes *= 0.7
        
        base_fc *= persona_scale
        base_fm *= persona_scale * burst_file_mult
        base_fd *= persona_scale * burst_file_mult
        base_bytes *= persona_scale * burst_file_mult

        delta_created = max(0.0, base_fc * phase_delta + random.uniform(0, 8))
        delta_modified = max(0.0, base_fm * phase_delta + random.uniform(0, 10))
        delta_deleted = max(0.0, base_fd * phase_delta + random.uniform(0, 6))
        delta_bytes = max(0.0, base_bytes * phase_delta + random.uniform(0, 15)) * 1024 * 1024
        delta_events = max(1, int(phase_delta * random.uniform(8, 60)))

        self.cumulative['files_created'] += delta_created
        self.cumulative['files_modified'] += delta_modified
        self.cumulative['files_deleted'] += delta_deleted
        self.cumulative['total_bytes_written'] += delta_bytes
        self.cumulative['_events_seen'] += delta_events
        
        if burst_entropy_mult > 1.5 and self.label == 1:
            self.causal.trigger(phase, 'entropy_spike', 'file_rename_patterns', 3.0, delay=0.2)
            self.causal.trigger(phase, 'entropy_spike', 'file_extension_anomaly', 2.5, delay=0.2)
        if delta_modified > 40 * phase_delta:
            self.causal.trigger(phase, 'file_burst', 'content_rewriting_patterns', 2.0, delay=0.2)

        process_age = phase * self.total_duration
        ts = self.base_ts + process_age + random.uniform(-2, 2)

        return self._short_term_features(phase, phase_delta, aggressive, burst_cpu_mult, burst_entropy_mult, burst_file_mult), {
            'pid': self.pid,
            'ppid': self.ppid,
            'host': self.host,
            'user': self.user,
            'image': self.image,
            '_process_age_sec': process_age,
            '_events_seen': self.cumulative['_events_seen'],
            'ts_epoch': ts,
        }

    def _short_term_features(self, phase: float, phase_delta: float, aggressive: bool, 
                             burst_cpu_mult: float, burst_entropy_mult: float, burst_file_mult: float) -> Dict[str, float]:
        slow = self.low_entropy
        causal_boosts = self.causal.get_boosts(phase)
        
        # Define stage variables early - used throughout the function for stage-aware features
        is_early_yara = phase <= 0.3
        is_mid_yara = 0.3 < phase <= 0.7
        is_late_yara = phase > 0.7
        
        # FIXED: Entropy features - increased overlap to reduce tight coupling
        # Goal: Allow benign edge cases to fully cross thresholds
        # Ransomware: Still higher on average, but with more low cases
        # Benign: More cases can reach high values (legitimate high-entropy operations)
        if self.label == 1:
            # Ransomware: 60% high entropy, 25% medium, 15% low (stealth)
            r = random.random()
            if self.low_entropy:
                # Low entropy flag: stealth ransomware
                base_entropy = random.uniform(5.0, 6.5)  # Can overlap with benign
            elif r < 0.6:
                # 60%: High entropy (typical ransomware encryption)
                base_entropy = random.uniform(7.5, 8.1)
            elif r < 0.85:
                # 25%: Medium entropy
                base_entropy = random.uniform(6.5, 7.5)  # Can overlap with benign high
            else:
                # 15%: Low entropy (stealth ransomware, legitimate-looking)
                base_entropy = random.uniform(5.0, 6.5)  # Can overlap with benign
        else:
            # Benign: More cases can reach high values (legitimate high-entropy operations)
            r = random.random()
            if self.persona in ['backup', 'compression', 'av_scan']:
                # These can have high entropy (legitimate)
                if r < 0.4:
                    # 40%: Very high entropy (legitimate compression/encryption)
                    base_entropy = random.uniform(7.0, 8.0)  # Can reach ransomware range
                else:
                    # 60%: High entropy
                    base_entropy = random.uniform(6.5, 7.5)
            elif self.persona == 'installer':
                # Installers: Can have moderate-high entropy
                if r < 0.2:
                    # 20%: High entropy (legitimate installer operations)
                    base_entropy = random.uniform(6.5, 7.5)
                else:
                    # 80%: Moderate-low entropy
                    base_entropy = random.uniform(5.0, 6.5)
            elif r < 0.15:
                # 15% of other benign: High entropy (legitimate high-entropy operations)
                base_entropy = random.uniform(6.5, 7.8)  # Can reach ransomware range
            elif r < 0.4:
                # 25%: Moderate entropy
                base_entropy = random.uniform(5.5, 6.5)
            else:
                # 60%: Lower entropy (typical benign)
                base_entropy = random.uniform(4.5, 6.0)
        
        entropy_trend = base_entropy * burst_entropy_mult
        entropy_trend += (phase - 0.5) * 0.6
        entropy_trend = _bounded(entropy_trend + random.uniform(-0.3, 0.3), 3.0, 8.1)
        
        # ENHANCED: entropy_velocity - Strengthened to contribute meaningfully (5-15% target)
        # Calculate base velocity from trend, but make it more discriminative
        base_velocity = (entropy_trend - 6.0) * 0.3 * burst_entropy_mult  # Increased multiplier
        
        if self.label == 1:
            # Ransomware: Higher velocity on average, but with variance
            # Stage-aware: velocity increases over time
            if is_early_yara:
                # Early: 50% chance of high velocity
                if random.random() < 0.5:
                    velocity_boost = random.uniform(0.2, 0.6)  # High velocity
                else:
                    velocity_boost = random.uniform(-0.1, 0.3)  # Low-medium
            elif is_mid_yara:
                # Mid: 70% chance of high velocity
                if random.random() < 0.7:
                    velocity_boost = random.uniform(0.3, 0.7)
                else:
                    velocity_boost = random.uniform(0.0, 0.4)
            else:  # is_late_yara
                # Late: 80% chance of high velocity
                if random.random() < 0.8:
                    velocity_boost = random.uniform(0.4, 0.8)
                else:
                    velocity_boost = random.uniform(0.1, 0.5)
            velocity_noise = random.uniform(-0.2, 0.2)  # Additional noise
        else:
            # Benign: Lower velocity on average, but significant overlap
            if self.persona in ['backup', 'compression', 'av_scan'] and random.random() < 0.4:
                # 40%: Moderate-high velocity (legitimate entropy changes)
                velocity_boost = random.uniform(0.1, 0.5)  # Significant overlap!
            elif random.random() < 0.2:
                # 20%: Moderate velocity
                velocity_boost = random.uniform(0.0, 0.3)
            else:
                # 80%: Low velocity
                velocity_boost = random.uniform(-0.3, 0.2)
            velocity_noise = random.uniform(-0.3, 0.3)
        
        entropy_velocity = _bounded(base_velocity + velocity_boost + velocity_noise, -1.0, 1.2)

        burstiness = _bounded((self.cumulative['files_modified'] / max(1.0, self.total_duration * phase)) * 10 * burst_file_mult + random.uniform(0, 6), 0, 50)

        cpu_usage = _bounded((70 if aggressive else 35) * phase * burst_cpu_mult + random.uniform(-10, 15), 0, 100)
        cpu_spike = _bounded(cpu_usage * 0.35 * burst_cpu_mult + random.uniform(0, 15), 0, 100)
        ram_usage = _bounded((40 if aggressive else 25) * phase * burst_cpu_mult + random.uniform(-5, 10), 0, 100)
        ram_spike = _bounded(ram_usage * 0.25 * burst_cpu_mult + random.uniform(0, 8), 0, 100)

        # ENHANCED: Network features - More overlap and variance
        if self.label == 1:
            # Ransomware: Stage-aware network activity
            if is_early_yara:
                net_conns = max(0.0, random.uniform(8, 18) * phase + random.uniform(-3, 5))
                dns = max(0.0, random.uniform(6, 14) * phase + random.uniform(-2, 4))
            elif is_mid_yara:
                net_conns = max(0.0, random.uniform(12, 20) * phase + random.uniform(-2, 4))
                dns = max(0.0, random.uniform(10, 16) * phase + random.uniform(-2, 3))
            else:  # is_late_yara
                net_conns = max(0.0, random.uniform(15, 25) * phase + random.uniform(-2, 4))
                dns = max(0.0, random.uniform(12, 18) * phase + random.uniform(-2, 3))
        else:
            # Benign: Can have high network activity (legitimate)
            if random.random() < random.uniform(0.15, 0.25):
                # 15-25%: High network activity (legitimate)
                net_conns = max(0.0, random.uniform(10, 20) * phase + random.uniform(-2, 4))
                dns = max(0.0, random.uniform(8, 15) * phase + random.uniform(-2, 3))
            else:
                # 75-85%: Low-moderate network activity
                net_conns = max(0.0, random.uniform(2, 8) * phase + random.uniform(-2, 3))
                dns = max(0.0, random.uniform(3, 8) * phase + random.uniform(-2, 2))
        
        # ENHANCED: uncommon_port - More overlap
        if self.label == 1:
            uncommon_port = random.random() < random.uniform(0.20, 0.30)  # 20-30% chance
        else:
            uncommon_port = random.random() < random.uniform(0.05, 0.10)  # 5-10% chance (legitimate)
        
        # ENHANCED: outbound_anom - More overlap
        if uncommon_port:
            outbound_anom = random.uniform(0.6, 0.9) if self.label == 1 else random.uniform(0.4, 0.7)  # Overlap
        else:
            outbound_anom = random.uniform(0.0, 0.3) if self.label == 1 else random.uniform(0.0, 0.2)
        
        # ENHANCED: Network features - Add more variance and overlap to prevent over-dominance
        # beacon_interval_std: Stage-aware with overlap
        if self.label == 1:
            # Ransomware: Stage-aware - more consistent in late stage
            if is_late_yara:
                # Late: 70% low std (consistent beaconing)
                if random.random() < 0.7:
                    beacon_interval_std = random.uniform(0.05, 0.15)
                else:
                    beacon_interval_std = random.uniform(0.15, 0.4)  # Some variance
            elif is_mid_yara:
                # Mid: 50% low std
                if random.random() < 0.5:
                    beacon_interval_std = random.uniform(0.05, 0.20)
                else:
                    beacon_interval_std = random.uniform(0.20, 0.6)
            else:  # is_early_yara
                # Early: 30% low std (not always beaconing early)
                if random.random() < 0.3:
                    beacon_interval_std = random.uniform(0.05, 0.25)
                else:
                    beacon_interval_std = random.uniform(0.25, 0.8)
        else:
            # Benign: Mostly high std, but 5-10% can have low std (legitimate consistent connections)
            if random.random() < random.uniform(0.05, 0.10):
                beacon_interval_std = random.uniform(0.1, 0.3)  # Overlap with ransomware
            else:
                beacon_interval_std = random.uniform(0.3, 0.9)
        
        # suspicious_tld: Add more variance
        if self.label == 1:
            # Ransomware: 30-40% chance (not always)
            suspicious_tld = random.random() < random.uniform(0.30, 0.40)
        else:
            # Benign: 3-6% false positive
            suspicious_tld = (self.overlap and random.random() < random.uniform(0.03, 0.06)) or (random.random() < 0.02)
        suspicious_tld_flag = 1.0 if suspicious_tld else 0.0
        
        # CRITICAL FIX: asn_risk_score - Stage-aware with MUCH more overlap to reduce dominance
        # This was causing ~50,000 gain importance - needs major rebalancing
        if self.label == 1:
            # Ransomware: Stage-aware probabilities, not always high
            if is_early_yara:
                # Early: 30-40% chance of high risk
                if random.random() < random.uniform(0.30, 0.40):
                    asn_risk_score = random.uniform(0.5, 0.9)
                else:
                    asn_risk_score = random.uniform(0.0, 0.5)  # Low-medium (significant overlap)
            elif is_mid_yara:
                # Mid: 40-50% chance of high risk
                if random.random() < random.uniform(0.40, 0.50):
                    asn_risk_score = random.uniform(0.6, 0.9)
                else:
                    asn_risk_score = random.uniform(0.1, 0.6)  # Medium overlap
            else:  # is_late_yara
                # Late: 50-60% chance of high risk
                if random.random() < random.uniform(0.50, 0.60):
                    asn_risk_score = random.uniform(0.65, 0.9)
                else:
                    asn_risk_score = random.uniform(0.2, 0.65)  # Medium overlap
        else:
            # Benign: MUCH more overlap - 15-25% can have moderate-high (legitimate risky ASNs)
            r = random.random()
            if r < random.uniform(0.15, 0.25):
                # 15-25%: Moderate-high risk (legitimate risky ASNs, VPNs, etc.)
                asn_risk_score = random.uniform(0.4, 0.8)  # MUCH more overlap!
            elif r < random.uniform(0.40, 0.55):
                # 20-30%: Moderate risk
                asn_risk_score = random.uniform(0.2, 0.5)
            else:
                # 45-60%: Low risk
                asn_risk_score = random.uniform(0.0, 0.3)
        
        # Add controlled noise to prevent perfect separability
        asn_risk_score += random.uniform(-0.05, 0.05)
        asn_risk_score = _bounded(asn_risk_score, 0.0, 1.0)
        
        # CRITICAL FIX: geo_risk_score - Stage-aware with MUCH more overlap to reduce dominance
        # This was causing ~270,000 gain importance - needs MAJOR rebalancing
        if self.label == 1:
            # Ransomware: Stage-aware probabilities, not always high
            if is_early_yara:
                # Early: 20-30% chance of high risk (not always)
                if random.random() < random.uniform(0.20, 0.30):
                    geo_risk_score = random.uniform(0.5, 0.9)
                else:
                    geo_risk_score = random.uniform(0.0, 0.5)  # Low-medium (significant overlap)
            elif is_mid_yara:
                # Mid: 30-40% chance of high risk
                if random.random() < random.uniform(0.30, 0.40):
                    geo_risk_score = random.uniform(0.6, 0.9)
                else:
                    geo_risk_score = random.uniform(0.1, 0.6)  # Medium overlap
            else:  # is_late_yara
                # Late: 40-50% chance of high risk
                if random.random() < random.uniform(0.40, 0.50):
                    geo_risk_score = random.uniform(0.65, 0.9)
                else:
                    geo_risk_score = random.uniform(0.2, 0.65)  # Medium overlap
        else:
            # Benign: MUCH more overlap - 15-25% can have moderate-high (legitimate risky geos)
            r = random.random()
            if r < random.uniform(0.15, 0.25):
                # 15-25%: Moderate-high risk (legitimate risky geos, VPNs, cloud services)
                geo_risk_score = random.uniform(0.4, 0.8)  # MUCH more overlap!
            elif r < random.uniform(0.40, 0.55):
                # 20-30%: Moderate risk
                geo_risk_score = random.uniform(0.2, 0.5)
            else:
                # 45-60%: Low risk
                geo_risk_score = random.uniform(0.0, 0.3)
        
        # Add controlled noise to prevent perfect separability
        geo_risk_score += random.uniform(-0.05, 0.05)
        geo_risk_score = _bounded(geo_risk_score, 0.0, 1.0)

        # FIXED: Crypto API usage - increased overlap to reduce tight coupling
        # Goal: Allow benign edge cases to fully cross thresholds
        # Ransomware: Still higher on average, but with more low cases
        # Benign: More cases can reach high values (legitimate encryption)
        if self.label == 1:
            # Ransomware: 60% high crypto usage, 25% medium, 15% low (stealth)
            r = random.random()
            if r > self.knobs.p_ransom_skips_obvious:
                # 60%: High crypto API usage (typical ransomware encryption)
                excessive_crypt = random.uniform(8.0, 15.0) * (1.0 + phase * 0.3)
            elif r > self.knobs.p_ransom_skips_obvious - 0.25:
                # 25%: Medium crypto usage
                excessive_crypt = random.uniform(4.0, 8.0) * (1.0 + phase * 0.2)
            else:
                # 15%: Low crypto usage (stealth ransomware, legitimate-looking)
                excessive_crypt = random.uniform(0.5, 5.0)  # Can overlap with benign high
        else:
            # Benign: More cases can reach high values (legitimate encryption)
            r = random.random()
            if self.persona in ['backup', 'av_scan'] and BENIGN_PERSONAS[self.persona].get('crypto_allowed'):
                # Backup/AV: Can have high crypto usage (legitimate encryption)
                if r < 0.5:
                    # 50%: High crypto usage (legitimate encryption operations)
                    excessive_crypt = random.uniform(6.0, 12.0)  # Can reach ransomware range
                else:
                    # 50%: Moderate crypto usage
                    excessive_crypt = random.uniform(2.0, 6.0)
            elif self.persona == 'compression':
                # Compression tools: Can use crypto (legitimate)
                if r < 0.3:
                    # 30%: High crypto usage
                    excessive_crypt = random.uniform(5.0, 10.0)  # Can reach ransomware range
                else:
                    # 70%: Low-moderate crypto usage
                    excessive_crypt = random.uniform(0.5, 4.0)
            elif self.overlap and random.random() < self.knobs.p_benign_hits_ransom_signals:
                # Overlap cases: Can have high crypto usage
                excessive_crypt = random.uniform(4.0, 9.0)  # Can reach ransomware range
            elif r < 0.1:
                # 10% of other benign: High crypto usage (legitimate encryption software)
                excessive_crypt = random.uniform(5.0, 10.0)  # Can reach ransomware range
            elif r < 0.3:
                # 20%: Moderate crypto usage
                excessive_crypt = random.uniform(2.0, 6.0)
            else:
                # 70%: Low or no crypto usage (typical benign)
                excessive_crypt = random.uniform(0.0, 3.0)
        
        # Ensure it's a reasonable value
        excessive_crypt = max(0.0, excessive_crypt)
        
        if excessive_crypt > 8 and self.label == 1:
            self.causal.trigger(phase, 'crypto_surge', 'cpu_usage_trend', 20.0, delay=0.2)

        # TASK 2: Strengthen supporting features - make them meaningfully contribute but non-dominant
        # These are computed after excessive_crypt is defined since some depend on it
        # Goal: All features contribute 5-15% each, no single feature >30%
        
        # encryption_progression_rate: Rate of encryption activity over time
        # Make it more discriminative but with significant overlap
        if self.label == 1:
            # Ransomware: Higher progression rate, but with more variance
            # Stage-aware: increases over time but not always high
            if is_early_yara:
                # Early: 50% chance of high, 50% chance of low-medium
                if random.random() < 0.5:
                    encryption_progression_rate = random.uniform(0.5, 0.9)
                else:
                    encryption_progression_rate = random.uniform(0.2, 0.5)  # Overlap with benign
            elif is_mid_yara:
                # Mid: 70% chance of high
                if random.random() < 0.7:
                    encryption_progression_rate = random.uniform(0.6, 0.9)
                else:
                    encryption_progression_rate = random.uniform(0.3, 0.6)
            else:  # is_late_yara
                # Late: 80% chance of high
                if random.random() < 0.8:
                    encryption_progression_rate = random.uniform(0.7, 0.9)
                else:
                    encryption_progression_rate = random.uniform(0.4, 0.7)
            # Add controlled noise
            encryption_progression_rate += random.uniform(-0.15, 0.15)
        else:
            # Benign: Lower progression, but significant overlap
            if self.persona in ['backup', 'compression'] and random.random() < 0.4:
                # 40%: Moderate-high (legitimate encryption)
                encryption_progression_rate = random.uniform(0.3, 0.7)  # Significant overlap!
            elif random.random() < 0.15:
                # 15%: Moderate (other legitimate encryption)
                encryption_progression_rate = random.uniform(0.2, 0.5)
            else:
                # 85%: Low
                encryption_progression_rate = random.uniform(0.0, 0.3)
        encryption_progression_rate = _bounded(encryption_progression_rate, 0.0, 1.0)
        
        # crypto_api_calls_rate: Rate of crypto API calls per unit time
        # Make it more discriminative with overlap
        if excessive_crypt > 0:
            base_rate = (excessive_crypt / max(1.0, phase * self.total_duration)) * 10.0
            # Add significant noise to prevent perfect correlation
            crypto_api_calls_rate = base_rate + random.uniform(-1.0, 1.0)
        else:
            # Even when no crypto, add some variance
            crypto_api_calls_rate = random.uniform(0.0, 0.8)  # Can overlap with low ransomware rates
        crypto_api_calls_rate = _bounded(crypto_api_calls_rate, 0.0, 20.0)
        
        # file_io_acceleration: Acceleration of file I/O operations
        # Make it more discriminative - ransomware has higher acceleration
        files_per_sec = self.cumulative['files_modified'] / max(0.1, self.total_duration * phase)
        prev_files_per_sec = self.cumulative.get('_prev_files_per_sec', 0.0)
        base_acceleration = (files_per_sec - prev_files_per_sec) / max(0.1, phase_delta)
        
        if self.label == 1:
            # Ransomware: Higher acceleration, but with variance
            file_io_acceleration = base_acceleration * random.uniform(1.2, 2.5)  # Boost ransomware
            file_io_acceleration += random.uniform(-3.0, 3.0)  # Add noise
        else:
            # Benign: Lower acceleration, but some can have moderate (backup, compression)
            if self.persona in ['backup', 'compression'] and random.random() < 0.3:
                file_io_acceleration = base_acceleration * random.uniform(0.8, 1.5)  # Moderate overlap
            else:
                file_io_acceleration = base_acceleration * random.uniform(0.3, 1.0)  # Lower
            file_io_acceleration += random.uniform(-2.0, 2.0)  # Add noise
        file_io_acceleration = _bounded(file_io_acceleration, -10.0, 50.0)
        self.cumulative['_prev_files_per_sec'] = files_per_sec
        
        # lifecycle_peak_file_rate: Peak file operation rate over lifecycle
        # Make it more discriminative
        current_rate = files_per_sec
        peak_rate = self.cumulative.get('_lifecycle_peak_file_rate', 0.0)
        if current_rate > peak_rate:
            peak_rate = current_rate
        self.cumulative['_lifecycle_peak_file_rate'] = peak_rate
        
        if self.label == 1:
            # Ransomware: Higher peak rates
            lifecycle_peak_file_rate = peak_rate * random.uniform(1.1, 1.5)  # Boost ransomware
        else:
            # Benign: Lower peak rates, but some overlap
            if self.persona in ['backup', 'compression'] and random.random() < 0.3:
                lifecycle_peak_file_rate = peak_rate * random.uniform(0.9, 1.2)  # Moderate overlap
            else:
                lifecycle_peak_file_rate = peak_rate * random.uniform(0.5, 1.0)  # Lower
        lifecycle_peak_file_rate += random.uniform(-1.0, 1.0)  # Add noise
        lifecycle_peak_file_rate = _bounded(lifecycle_peak_file_rate, 0.0, 100.0)

        # CRITICAL FIX: mem_anomaly - Stage-aware with MUCH more overlap to reduce dominance
        # This affects writexecutable_memory_regions which was causing ~70,000 gain importance
        if self.label == 1:
            # Ransomware: Stage-aware probabilities, not always high
            if is_early_yara:
                # Early: 50-60% chance of high anomaly
                if random.random() < random.uniform(0.50, 0.60):
                    mem_anomaly = random.uniform(0.6, 0.95)
                else:
                    mem_anomaly = random.uniform(0.2, 0.6)  # Medium-low (evasion, overlap)
            elif is_mid_yara:
                # Mid: 60-70% chance of high anomaly
                if random.random() < random.uniform(0.60, 0.70):
                    mem_anomaly = random.uniform(0.65, 0.95)
                else:
                    mem_anomaly = random.uniform(0.3, 0.65)  # Medium overlap
            else:  # is_late_yara
                # Late: 70-80% chance of high anomaly
                if random.random() < random.uniform(0.70, 0.80):
                    mem_anomaly = random.uniform(0.7, 0.95)
                else:
                    mem_anomaly = random.uniform(0.4, 0.7)  # Medium overlap
        else:
            # Benign: MUCH more overlap - 20-30% can have moderate-high (legitimate memory operations)
            r = random.random()
            if r < random.uniform(0.20, 0.30):
                # 20-30%: Moderate-high anomaly (legitimate memory operations, debuggers, etc.)
                mem_anomaly = random.uniform(0.4, 0.7)  # MUCH more overlap!
            elif r < random.uniform(0.45, 0.60):
                # 20-30%: Moderate anomaly
                mem_anomaly = random.uniform(0.2, 0.5)
            else:
                # 40-55%: Low anomaly
                mem_anomaly = random.uniform(0.0, 0.3)
        
        # Add controlled noise to prevent perfect separability
        mem_anomaly += random.uniform(-0.05, 0.05)
        mem_anomaly = _bounded(mem_anomaly, 0.0, 1.0)
        
        # priv_escalation: Add more variance
        if self.label == 1:
            # Ransomware: 25% chance (not always)
            priv_escalation = 1.0 if random.random() < 0.25 else 0.0
        else:
            # Benign: 2-5% false positive (legitimate privilege operations)
            priv_escalation = 1.0 if random.random() < random.uniform(0.02, 0.05) else 0.0
        
        # honeypot: Add more variance
        if self.label == 1:
            # Ransomware: 10-15% chance (not always)
            honeypot = 1.0 if random.random() < random.uniform(0.10, 0.15) else 0.0
        else:
            # Benign: 1-3% false positive
            honeypot = 1.0 if (self.overlap and random.random() < random.uniform(0.01, 0.03)) else 0.0
        
        # FIXED: parent_child_anomaly_score - reduce over-dominance further by widening overlap
        # Goal: keep the signal useful, but stop it from becoming the primary shortcut feature
        # Malicious: more mixed distribution across high/medium/low
        # Benign: realistic overlap for installers, updaters, compression, and dev tools
        if self.label == 1:
            # Ransomware: mostly high anomaly, but some can be lower (stealth)
            r = random.random()
            if self.unusual_parent:
                # Unusual parent (e.g., winword.exe → powershell.exe): high anomaly
                parent_anom = random.uniform(0.55, 0.85)
            elif r < 0.45:
                # 45%: High anomaly (typical ransomware pattern)
                parent_anom = random.uniform(0.5, 0.82)
            elif r < 0.85:
                # 40%: Medium anomaly
                if self.spawn_depth > 3:
                    parent_anom = random.uniform(0.28, 0.58)
                else:
                    parent_anom = random.uniform(0.22, 0.5)
            else:
                # 15%: Low anomaly (stealth ransomware, legitimate-looking)
                parent_anom = random.uniform(0.05, 0.3)
        else:
            # Benign: mostly low-medium, but some can have high (installers, dev tools)
            r = random.random()
            if self.unusual_parent or (self.persona == 'installer' and r < 0.3):
                # Installers and dev tools can have unusual parents (legitimate)
                parent_anom = random.uniform(0.4, 0.74)  # High but legitimate
            elif r < 0.15:
                # 15%: High anomaly (legitimate cases: installers, dev tools, complex apps)
                parent_anom = random.uniform(0.4, 0.7)
            elif r < 0.55:
                # 40%: Medium anomaly
                if self.spawn_depth > 3:
                    parent_anom = random.uniform(0.22, 0.52)
                else:
                    parent_anom = random.uniform(0.12, 0.42)
            else:
                # 45%: Low anomaly (typical benign processes)
                parent_anom = random.uniform(0.0, 0.25)
        
        parent_anom = _bounded(parent_anom, 0.0, 1.0)
        
        # CRITICAL FIX: yara_match_strength - Make stage-aware and probabilistic to reduce dominance
        # Stage-aware probabilities to prevent perfect separability
        is_early = phase <= 0.3
        is_mid = 0.3 < phase <= 0.7
        is_late = phase > 0.7
        
        yara_match_strength = 0.0
        if self.label == 1:
            # Ransomware: Stage-aware probabilistic YARA matches
            if is_early:
                # Early stage: 30-40% chance of YARA match (not all ransomware detected early)
                if random.random() < random.uniform(0.30, 0.40):
                    yara_match_strength = random.choice([1.0, 2.0, 3.0])
            elif is_mid:
                # Mid stage: 50-60% chance
                if random.random() < random.uniform(0.50, 0.60):
                    yara_match_strength = random.choice([1.0, 2.0, 3.0])
            else:  # is_late
                # Late stage: 60-75% chance (more likely to be detected)
                if random.random() < random.uniform(0.60, 0.75):
                    yara_match_strength = random.choice([1.0, 2.0, 3.0])
        else:
            # Benign: 5-12% chance of false positive YARA matches (realistic)
            benign_yara_prob = random.uniform(0.05, 0.12)
            if random.random() < benign_yara_prob:
                yara_match_strength = 1.0  # Low strength false positive

        # TASK 1: file_extension_anomaly - Stage-aware probabilistic behavior to reduce dominance
        # Stage-aware probabilities:
        #   Early (phase <= 0.3): 20-30% chance for ransomware, 3-5% for benign
        #   Mid (0.3 < phase <= 0.7): 50-60% chance for ransomware, 4-6% for benign
        #   Late (phase > 0.7): 70-85% chance for ransomware, 5-8% for benign
        # This prevents perfect separability and makes the feature more realistic
        
        # Determine stage
        is_early = phase <= 0.3
        is_mid = 0.3 < phase <= 0.7
        is_late = phase > 0.7
        
        if self.label == 1:
            # Ransomware: Stage-aware probabilistic behavior
            if is_early:
                # Early stage: 20-30% chance of high file extension anomaly
                if random.random() < random.uniform(0.20, 0.30):
                    file_ext_base = random.uniform(5.0, 9.0)  # High when present
                else:
                    file_ext_base = random.uniform(0.0, 2.0)  # Low/absent (70-80% of early cases)
            elif is_mid:
                # Mid stage: 50-60% chance
                if random.random() < random.uniform(0.50, 0.60):
                    file_ext_base = random.uniform(6.0, 10.0)  # High when present
                else:
                    file_ext_base = random.uniform(0.5, 4.0)  # Low/medium (40-50% of mid cases)
            else:  # is_late
                # Late stage: 70-85% chance
                if random.random() < random.uniform(0.70, 0.85):
                    file_ext_base = random.uniform(7.0, 10.0)  # High when present
                else:
                    file_ext_base = random.uniform(1.0, 5.0)  # Low/medium (15-30% of late cases)
            
            # File rename and content rewrite (not stage-aware, keep existing logic)
            r = random.random()
            if r < 0.6:
                file_rename_base = random.uniform(4.0, 8.0)
                content_rewrite_base = random.uniform(5.0, 9.0)
            elif r < 0.85:
                file_rename_base = random.uniform(2.0, 5.0)
                content_rewrite_base = random.uniform(2.0, 5.0)
            else:
                file_rename_base = random.uniform(0.5, 2.5)
                content_rewrite_base = random.uniform(0.5, 3.0)
        else:
            # Benign: Low probability of file extension anomaly (3-8% depending on stage)
            if is_early:
                benign_prob = random.uniform(0.03, 0.05)
            elif is_mid:
                benign_prob = random.uniform(0.04, 0.06)
            else:  # is_late
                benign_prob = random.uniform(0.05, 0.08)
            
            if random.random() < benign_prob:
                # Benign with file extension anomaly (backup, compression, installers)
                if self.persona in ['backup', 'compression', 'installer']:
                    file_ext_base = random.uniform(3.0, 7.0)  # Moderate-high
                else:
                    file_ext_base = random.uniform(2.0, 5.0)  # Moderate
            else:
                # Typical benign: very low or zero
                file_ext_base = random.uniform(0.0, 1.5)
            
            # File rename and content rewrite for benign (keep existing logic)
            r = random.random()
            if self.persona in ['backup', 'compression']:
                if r < 0.5:
                    file_rename_base = random.uniform(3.0, 7.0)
                    content_rewrite_base = random.uniform(3.0, 7.0)
                else:
                    file_rename_base = random.uniform(1.5, 4.0)
                    content_rewrite_base = random.uniform(1.5, 4.0)
            elif self.persona == 'installer':
                if r < 0.3:
                    file_rename_base = random.uniform(2.5, 6.0)
                    content_rewrite_base = random.uniform(2.0, 5.5)
                else:
                    file_rename_base = random.uniform(0.5, 3.0)
                    content_rewrite_base = random.uniform(0.5, 3.0)
            elif r < 0.15:
                file_rename_base = random.uniform(2.0, 6.0)
                content_rewrite_base = random.uniform(2.0, 5.0)
            elif r < 0.4:
                file_rename_base = random.uniform(1.0, 4.0)
                content_rewrite_base = random.uniform(1.0, 4.0)
            else:
                file_rename_base = random.uniform(0.0, 2.0)
                content_rewrite_base = random.uniform(0.0, 2.0)
        
        # Add controlled noise to prevent perfect separability
        file_ext_noise = random.uniform(-0.3, 0.3)  # Bounded, explainable noise
        file_rename = file_rename_base + causal_boosts.get('file_rename_patterns', 0.0)
        file_ext_anomaly = file_ext_base + file_ext_noise + causal_boosts.get('file_extension_anomaly', 0.0)
        content_rewrite = content_rewrite_base + causal_boosts.get('content_rewriting_patterns', 0.0)
        
        cpu_usage_adjusted = cpu_usage + causal_boosts.get('cpu_usage_trend', 0.0)
        cpu_usage_adjusted = _bounded(cpu_usage_adjusted, 0, 100)
        
        # FIXED: signature_trust_level - removed data leakage, added realistic overlap
        # Malicious: 70% low trust, 20% medium, 10% high (evasion/signed malware)
        # Benign: 80% high trust, 15% medium, 5% low (legitimate unsigned software)
        if self.label == 1:
            r = random.random()
            if r < 0.7:
                signature_trust_level = random.uniform(0.0, 0.3)  # Low trust
            elif r < 0.9:
                signature_trust_level = random.uniform(0.3, 0.6)  # Medium trust
            else:
                signature_trust_level = random.uniform(0.6, 0.8)  # High trust (evasion)
        else:
            r = random.random()
            if r < 0.8:
                signature_trust_level = random.uniform(0.5, 1.0)  # High trust
            elif r < 0.95:
                signature_trust_level = random.uniform(0.3, 0.5)  # Medium trust
            else:
                signature_trust_level = random.uniform(0.0, 0.3)  # Low trust (legitimate unsigned)
        
        # FIXED: is_microsoft_signed - improved overlap for realism
        # Malicious: 70% unsigned, 20% signed (signed malware), 10% ambiguous
        # Benign: 85% signed, 10% unsigned (legitimate unsigned), 5% ambiguous
        if self.label == 1:
            r = random.random()
            if r < 0.7:
                is_microsoft_signed_val = 0.0  # Unsigned malware
            elif r < 0.9:
                is_microsoft_signed_val = 1.0  # Signed malware (evasion)
            else:
                is_microsoft_signed_val = random.choice([0.0, 1.0])  # Ambiguous
        else:
            r = random.random()
            if r < 0.85:
                is_microsoft_signed_val = 1.0  # Signed legitimate
            elif r < 0.95:
                is_microsoft_signed_val = 0.0  # Unsigned legitimate (open source, etc.)
            else:
                is_microsoft_signed_val = random.choice([0.0, 1.0])  # Ambiguous
        
        # FIXED: cert_mismatch_tampering - improved overlap
        # Malicious: 40% tampering, 60% no tampering
        # Benign: 5% tampering (legitimate cert issues), 95% no tampering
        if self.label == 1:
            cert_mismatch_tampering_val = 1.0 if random.random() < 0.4 else 0.0
        else:
            cert_mismatch_tampering_val = 1.0 if random.random() < 0.05 else 0.0
        
        # CRITICAL FIX: Compute YARA features BEFORE return dictionary
        # Stage variables already defined at function start (is_early_yara, is_mid_yara, is_late_yara)
        
        # YARA match flags - stage-aware probabilities
        if self.label == 1:
            # Ransomware: Stage-aware probabilities (not always detected)
            yara_mem_prob = random.uniform(0.25, 0.45) if is_late_yara else random.uniform(0.15, 0.30) if is_mid_yara else random.uniform(0.10, 0.25)
            yara_exec_prob = random.uniform(0.30, 0.50) if is_late_yara else random.uniform(0.20, 0.35) if is_mid_yara else random.uniform(0.15, 0.30)
            yara_script_prob = random.uniform(0.20, 0.35) if (self.lolbin and is_late_yara) else random.uniform(0.10, 0.25) if (self.lolbin and is_mid_yara) else random.uniform(0.05, 0.15) if self.lolbin else 0.0
        else:
            # Benign: 3-8% false positive rate (realistic)
            yara_mem_prob = random.uniform(0.03, 0.08)
            yara_exec_prob = random.uniform(0.03, 0.08)
            yara_script_prob = random.uniform(0.02, 0.06) if self.lolbin else 0.0
        
        yara_match_memory_val = 1.0 if random.random() < yara_mem_prob else 0.0
        yara_match_executable_val = 1.0 if random.random() < yara_exec_prob else 0.0
        yara_match_script_val = 1.0 if random.random() < yara_script_prob else 0.0
        
        # CRITICAL FIX: yara_weighted_confidence - Stage-aware with significant overlap
        # This was causing 70% dominance - needs major rebalancing
        if self.label == 1:
            # Ransomware: Stage-aware confidence, not always high
            if is_early_yara:
                # Early: 40-60% chance of high confidence, 40-60% chance of low/medium
                if random.random() < random.uniform(0.40, 0.60):
                    yara_weighted_confidence_val = random.uniform(0.6, 0.95)  # High confidence
                else:
                    yara_weighted_confidence_val = random.uniform(0.1, 0.6)  # Low-medium (evasion, no match)
            elif is_mid_yara:
                # Mid: 50-70% chance of high confidence
                if random.random() < random.uniform(0.50, 0.70):
                    yara_weighted_confidence_val = random.uniform(0.7, 0.95)
                else:
                    yara_weighted_confidence_val = random.uniform(0.2, 0.7)
            else:  # is_late_yara
                # Late: 60-80% chance of high confidence
                if random.random() < random.uniform(0.60, 0.80):
                    yara_weighted_confidence_val = random.uniform(0.75, 0.95)
                else:
                    yara_weighted_confidence_val = random.uniform(0.3, 0.75)
        else:
            # Benign: Significant overlap - 10-20% can have moderate-high confidence (false positives)
            r = random.random()
            if r < random.uniform(0.10, 0.20):
                # 10-20%: Moderate-high confidence (legitimate security tools, packers, etc.)
                yara_weighted_confidence_val = random.uniform(0.4, 0.8)  # Significant overlap!
            elif r < random.uniform(0.30, 0.50):
                # 20-30%: Low-medium confidence
                yara_weighted_confidence_val = random.uniform(0.1, 0.5)
            else:
                # 50-60%: Very low or zero confidence
                yara_weighted_confidence_val = random.uniform(0.0, 0.3)
        
        # Add controlled noise to prevent perfect separability
        yara_weighted_confidence_val += random.uniform(-0.05, 0.05)
        yara_weighted_confidence_val = _bounded(yara_weighted_confidence_val, 0.0, 1.0)
        
        return {
            'entropy_trend': entropy_trend,
            'entropy_velocity': entropy_velocity,
            'encryption_progression_rate': encryption_progression_rate,
            'crypto_api_calls_rate': crypto_api_calls_rate,
            'file_io_acceleration': file_io_acceleration,
            'lifecycle_peak_file_rate': lifecycle_peak_file_rate,
            'burstiness_file_io': burstiness,
            'cpu_usage_trend': cpu_usage_adjusted,
            'cpu_spike_deviation': cpu_spike,
            'ram_usage_trend': ram_usage,
            'sudden_ram_spikes': ram_spike,
            'thread_count_delta': _bounded(30 * phase + random.uniform(-5, 8), 0, 200),
            'handle_count_delta': _bounded(80 * phase + random.uniform(-10, 15), 0, 400),
            'network_connections': net_conns,
            'dns_lookup_count': dns,
            'outbound_connection_anomaly': outbound_anom,
            'total_sockets_created': net_conns * (1.2 + random.random()),
            # ENHANCED: unexpected_ports_touched - More overlap
            'unexpected_ports_touched': (random.uniform(4.0, 6.0) if uncommon_port else random.uniform(0.0, 2.0)) if self.label == 1 else (random.uniform(2.0, 5.0) if uncommon_port else random.uniform(0.0, 1.5)),
            # ENHANCED: unusual_destination_ip_behavior - More overlap
            'unusual_destination_ip_behavior': (random.uniform(0.8, 1.0) if uncommon_port else random.uniform(0.0, 0.3)) if self.label == 1 else (random.uniform(0.5, 0.8) if uncommon_port else random.uniform(0.0, 0.2)),
            'beacon_interval_std': beacon_interval_std,
            'suspicious_tld_flag': suspicious_tld_flag,
            'asn_risk_score': asn_risk_score,
            'geo_risk_score': geo_risk_score,
            'signature_trust_level': signature_trust_level,
            'is_microsoft_signed': is_microsoft_signed_val,
            'cert_mismatch_tampering': cert_mismatch_tampering_val,
            'parent_child_anomaly_score': parent_anom,
            # ENHANCED: unexpected_spawning_patterns - More overlap
            'unexpected_spawning_patterns': (1.0 if random.random() < random.uniform(0.25, 0.35) else random.uniform(0.0, 0.3)) if self.label == 1 else (random.uniform(0.0, 0.2) if random.random() < random.uniform(0.10, 0.15) else random.uniform(0.0, 0.1)),
            'spawn_depth': float(self.spawn_depth),
            'injection_edge_flag': 1.0 if self.has_injection_edge else 0.0,
            'shared_handles_flag': 1.0 if self.has_shared_handles else 0.0,
            # ENHANCED: working_directory_anomaly - More overlap
            # REBALANCED: working_directory_anomaly - MAJOR OVERLAP (benign 30-40%, was ~10%)
            'working_directory_anomaly': (
                (1.0 if random.random() < 0.55 else random.uniform(0.2, 0.6))  # Malicious: 55% certainty (was ~30%)
                if self.label == 1 else 
                (random.uniform(0.3, 0.7) if random.random() < 0.35 else random.uniform(0.0, 0.3))  # Benign: 35% trigger (was ~10%)
            ),
            # REBALANCED: executable_path_mismatch - MAJOR OVERLAP (benign 35-45%, was ~7%)
            'executable_path_mismatch': (
                (1.0 if random.random() < 0.58 else random.uniform(0.2, 0.65))  # Malicious: 58% certainty (was ~25%)
                if self.label == 1 else 
                (random.uniform(0.3, 0.8) if random.random() < 0.40 else random.uniform(0.0, 0.3))  # Benign: 40% trigger (was ~7%)
            ),
            # ENHANCED: image_memory_disk_mismatch - Add variance to prevent over-dominance
            'image_memory_disk_mismatch': _bounded(mem_anomaly + random.uniform(-0.1, 0.1), 0.0, 1.0),  # Add noise
            # REBALANCED: unsigned_image_mapped - MAJOR OVERLAP (benign 30-40%, was ~12%)
            'unsigned_image_mapped': (
                (1.0 if random.random() < 0.62 else random.uniform(0.2, 0.7))  # Malicious: 62% certainty (was ~40%)
                if self.label == 1 else 
                (random.uniform(0.3, 0.8) if random.random() < 0.35 else random.uniform(0.0, 0.3))  # Benign: 35% trigger (was ~12%)
            ),
            'writexecutable_memory_regions': mem_anomaly,  # Already fixed via mem_anomaly
            'memory_region_entropy_anomalies': _bounded(mem_anomaly * 0.8 + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'thread_start_address_anomalies': _bounded(mem_anomaly * 0.5 + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'module_load_anomaly_score': _bounded(0.6 * mem_anomaly + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'unexpected_dlls_loaded': _bounded(3.0 * mem_anomaly + random.uniform(-0.2, 0.2), 0.0, 10.0),  # Add noise
            # REBALANCED: dlls_unusual_directories - MAJOR OVERLAP INCREASE (was 5-10% benign, now 40-50%)
            'dlls_unusual_directories': (
                (1.0 if random.random() < 0.60 else random.uniform(0.2, 0.7))  # Malicious: 60% certainty (was ~80%)
                if self.label == 1 else 
                (random.uniform(0.4, 0.9) if random.random() < 0.45 else random.uniform(0.0, 0.4))  # Benign: 45% trigger (was ~7%)
            ),
            'suspicious_api_call_frequency': 8.0 * (1.0 if excessive_crypt > 0 else 0.0) + random.uniform(0, 3),
            'excessive_crypt_apis': excessive_crypt,
            'excessive_virtualalloc': _bounded(mem_anomaly * 5 + random.uniform(-0.5, 0.5), 0.0, 10.0),  # Add noise
            'excessive_writeprocessmemory': _bounded(mem_anomaly * 5 + random.uniform(-0.5, 0.5), 0.0, 10.0),  # Add noise
            'excessive_createremotethread': _bounded(mem_anomaly * 3 + random.uniform(-0.3, 0.3), 0.0, 8.0),  # Add noise
            'token_privilege_escalation': priv_escalation,  # Already fixed
            'unexpected_privilege_acquisition': priv_escalation,  # Already fixed
            'access_token_manipulation': _bounded(priv_escalation * 0.8 + random.uniform(-0.1, 0.1), 0.0, 1.0),  # Add noise
            # REBALANCED: registry_modification_anomaly - More overlap
            'registry_modification_anomaly': (
                (1.0 if random.random() < 0.60 else random.uniform(0.2, 0.7)) 
                if self.label == 1 else 
                (random.uniform(0.2, 0.6) if random.random() < 0.25 else random.uniform(0.0, 0.2))  # 25% benign trigger
            ),
            # REBALANCED: scheduled_task_creation_attempts - MAJOR OVERLAP (benign 30-40%, was ~7%)
            'scheduled_task_creation_attempts': (
                (1.0 if random.random() < 0.55 else random.uniform(0.2, 0.65))  # Malicious: 55% certainty (was ~30%)
                if self.label == 1 else 
                (random.uniform(0.3, 0.7) if random.random() < 0.35 else random.uniform(0.0, 0.3))  # Benign: 35% trigger (was ~7%)
            ),
            'process_created_suspended': 1.0 if self.lolbin else 0.0,
            'ntunmapviewofsection_usage': _bounded(mem_anomaly * 0.3 + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'large_writeprocessmemory_activity': _bounded(mem_anomaly * 0.6 + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'thread_resume_sequence_anomalies': _bounded(mem_anomaly * 0.4 + random.uniform(-0.05, 0.05), 0.0, 1.0),  # Add noise
            'file_rename_patterns': _bounded(file_rename, 0, 15),
            'file_extension_anomaly': _bounded(file_ext_anomaly, 0, 15),
            'content_rewriting_patterns': _bounded(content_rewrite, 0, 15),
            'suspicious_honeypot_access': honeypot,  # Already fixed
            # ENHANCED: user_interactivity_anomaly - More overlap
            'user_interactivity_anomaly': (random.uniform(0.4, 0.6) if random.random() < random.uniform(0.15, 0.25) else random.uniform(0.0, 0.3)) if self.label == 1 else (random.uniform(0.0, 0.2) if random.random() < random.uniform(0.08, 0.12) else random.uniform(0.0, 0.1)),
            'unexpected_gui_access': random.uniform(0.0, 0.4) if random.random() < random.uniform(0.10, 0.20) else random.uniform(0.0, 0.2),  # More variance
            'unexpected_clipboard_access': random.uniform(0.0, 0.4) if random.random() < random.uniform(0.10, 0.20) else random.uniform(0.0, 0.2),  # More variance
            'temporal_correlation_spikes': _bounded(burstiness * 0.3 + random.uniform(-0.5, 0.5), 0.0, 20.0),  # Add noise
            'baseline_deviation_score': _bounded(0.5 * mem_anomaly + 0.2 * burstiness + random.uniform(-0.1, 0.1), 0.0, 1.0),  # Add noise
            # YARA features (computed above to reduce dominance)
            'yara_match_memory': yara_match_memory_val,
            'yara_match_executable': yara_match_executable_val,
            'yara_match_script': yara_match_script_val,
            'yara_match_document': 0.0,  # Rare for ransomware
            'yara_match_ads': 0.0,  # Rare
            'yara_weighted_confidence': yara_weighted_confidence_val,
            'yara_match_strength': yara_match_strength,
        }


# ========================================================================================
# SECTION 13: GENERATION
# ========================================================================================

def build_pid_rows(state: PIDState, knobs: Knobs) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for phase in SNAPSHOT_PHASES:
        short_features, meta = state.advance(phase)
        stage3_score, stage3_tier = _derive_stage3_score_and_tier(short_features)
        
        cmdline = _generate_cmdline(state.image, state.label)
        yara_family = ''
        if short_features.get('yara_match_strength', 0) >= 2:
            yara_family = random.choice(['crypto', 'packer', 'loader', 'ransomware'])
        
        record: Dict[str, object] = {
            'event_uuid': str(uuid.uuid4()),
            'ts_epoch': meta['ts_epoch'],
            'host': meta['host'],
            'pid': meta['pid'],
            'ppid': meta['ppid'],
            'image': state.image,
            'command_line': cmdline,
            'process_tree_id': state.tree_id,
            'parent_image': state.parent_image,
            'session_id': state.session_id,
            'logon_type': state.logon_type,
            'is_elevated': 1.0 if state.is_elevated else 0.0,
            'uac_bypass_suspected': 1.0 if state.uac_bypass else 0.0,
            'stage2_promoted': state.label == 1 or random.random() < 0.05,
            'stage2_score': random.uniform(5, 15) if state.label == 1 else random.uniform(0, 8),
            'stage3_score': stage3_score,
            'stage3_tier': stage3_tier,
            'yara_context': 'EXECUTABLE' if short_features.get('yara_match_executable') else 'NONE',
            'yara_context_weight': short_features.get('yara_weighted_confidence', 0.0),
            'yara_weighted_confidence': short_features.get('yara_weighted_confidence', 0.0),
            'yara_boost': 0.0,
            'yara_escalation_allowed': True,
            'yara_family': yara_family,
            'behavioral_signal_count': int(sum(1 for v in short_features.values() if isinstance(v, (int, float)) and v != 0)),
            'yara_downweight_reason': '' if state.label == 1 else 'low_trust',
            'label': state.label,
            '_snapshot_phase': phase,
            '_process_age_sec': meta['_process_age_sec'],
            '_events_seen': meta['_events_seen'],
            '_snapshot_method': 'fractional_time',
            'files_created': state.cumulative['files_created'],
            'files_modified': state.cumulative['files_modified'],
            'files_deleted': state.cumulative['files_deleted'],
            'total_bytes_written': state.cumulative['total_bytes_written'],
            '_adversarial_technique': state.adversarial_technique or '',
            '_attack_stage_count': len(state.attack_chain),
            '_c2_protocol': state.c2_profile.get('protocol', ''),
            '_persistence_count': len(state.persistence_mechanisms),
        }

        # Derive rate-based features to match runtime extractor (avoid constant-zero columns)
        age_sec = max(0.1, meta['_process_age_sec'])
        files_created_rate = state.cumulative['files_created'] / age_sec
        files_deleted_rate = state.cumulative['files_deleted'] / age_sec
        bytes_written_rate = state.cumulative['total_bytes_written'] / age_sec

        # Medium/long-term rates as smoothed variants with noise
        rate_noise = random.uniform(0.7, 1.3)
        medium_term_file_rate = (state.cumulative['files_modified'] / max(1.0, age_sec * 0.6)) * rate_noise
        long_term_file_rate = (state.cumulative['files_modified'] / max(1.0, age_sec * 1.5)) * random.uniform(0.6, 1.2)

        # Attach only if not already present in short_features
        for key, value in {
            'files_created_rate': files_created_rate,
            'files_deleted_rate': files_deleted_rate,
            'bytes_written_rate': bytes_written_rate,
            'medium_term_file_rate': medium_term_file_rate,
            'long_term_file_rate': long_term_file_rate,
        }.items():
            if key not in short_features:
                record[key] = float(value)

        record.update(short_features)
        
        for key in ['command_line', 'image', 'host']:
            _maybe_missing(record, key, knobs.p_noise_missing)
        
        rows.append(record)
        
        if random.random() < knobs.p_noise_duplicate:
            dup = record.copy()
            dup['event_uuid'] = str(uuid.uuid4())
            rows.append(dup)
    
    if random.random() < knobs.p_out_of_order:
        random.shuffle(rows)
    return rows


def check_feature_dominance(df: pd.DataFrame, knobs: 'Knobs') -> List[Dict[str, any]]:
    """TASK 3: Post-generation validation - Check feature dominance using variance ratio.
    
    Computes a proxy for feature importance using variance ratio between malicious/benign.
    Flags features contributing >30-35% dominance.
    
    Args:
        df: Generated dataset
        knobs: Generator configuration
    
    Returns:
        List of dominance reports (empty if no issues)
    """
    if 'label' not in df.columns:
        return []
    
    label_col = df['label']
    malicious_mask = label_col == 1
    benign_mask = label_col == 0
    
    if malicious_mask.sum() == 0 or benign_mask.sum() == 0:
        return []  # Cannot compute dominance without both classes
    
    # Compute variance ratio for each feature (proxy for importance)
    feature_dominance = {}
    feature_names = [f for f in EXPECTED_FEATURES if f in df.columns]
    
    # Metadata columns to skip
    meta_cols = {'label', 'Label', 'malicious', 'event_uuid', 'pid', 'ppid', 'process_tree_id', 
                 'host', 'image', 'command_line', 'parent_image', 'user', 'session_id', 
                 'logon_type', 'is_elevated', 'uac_bypass_suspected', '_snapshot_phase', 
                 '_process_age_sec', '_events_seen', '_snapshot_method', 'ts_epoch'}
    
    for feature in feature_names:
        if feature in meta_cols:
            continue
        
        malicious_vals = df.loc[malicious_mask, feature]
        benign_vals = df.loc[benign_mask, feature]
        
        # Skip if constant or mostly constant
        if malicious_vals.std() < 1e-6 and benign_vals.std() < 1e-6:
            continue
        
        # Compute variance ratio (higher = more discriminative)
        malicious_var = malicious_vals.var()
        benign_var = benign_vals.var()
        mean_diff = abs(malicious_vals.mean() - benign_vals.mean())
        
        # Combined metric: variance ratio + mean difference
        if benign_var > 1e-6:
            variance_ratio = malicious_var / benign_var
        else:
            variance_ratio = malicious_var if malicious_var > 1e-6 else 0.0
        
        # Normalize mean difference by combined std
        combined_std = np.sqrt((malicious_var + benign_var) / 2)
        if combined_std > 1e-6:
            normalized_diff = mean_diff / combined_std
        else:
            normalized_diff = 0.0
        
        # Dominance score: combination of variance ratio and normalized difference
        dominance_score = (variance_ratio * 0.5) + (normalized_diff * 0.5)
        feature_dominance[feature] = dominance_score
    
    if not feature_dominance:
        return []
    
    # Normalize to percentages
    total_dominance = sum(feature_dominance.values())
    if total_dominance == 0:
        return []
    
    feature_percentages = {f: (score / total_dominance) * 100 for f, score in feature_dominance.items()}
    
    # Sort by dominance
    sorted_features = sorted(feature_percentages.items(), key=lambda x: x[1], reverse=True)
    
    # Check for over-dominant features (>30% threshold)
    dominance_threshold = 30.0  # 30% threshold
    warnings = []
    
    for feature, percentage in sorted_features[:5]:  # Top 5 features
        status = "OK"
        recommendation = None
        
        if percentage > dominance_threshold:
            status = "WARNING – rebalance recommended"
            recommendation = f"Feature '{feature}' contributes {percentage:.2f}% of total dominance. " \
                           f"Consider: (1) Reducing correlation with label, (2) Adding more overlap " \
                           f"with benign samples, (3) Introducing stage-aware probabilistic behavior."
        elif percentage > 20.0:
            status = "CAUTION – monitor"
            recommendation = f"Feature '{feature}' is moderately dominant ({percentage:.2f}%). " \
                           f"Consider monitoring and rebalancing if it increases further."
        
        warnings.append({
            'feature': feature,
            'dominance': percentage / 100.0,  # As fraction
            'status': status,
            'recommendation': recommendation
        })
    
    return warnings


def validate_df(df: pd.DataFrame) -> Dict[str, object]:
    if 'label' not in df.columns:
        raise SystemExit("Validation failed: label column missing")
    bad_labels = set(df['label'].unique()) - {0, 1}
    if bad_labels:
        raise SystemExit(f'Validation failed: non-binary labels found: {bad_labels}')

    phase_counts = df.groupby('pid')['_snapshot_phase'].nunique()
    if (phase_counts != len(SNAPSHOT_PHASES)).any():
        raise SystemExit('Validation failed: snapshot phase completeness violated')

    missing_feats = [f for f in EXPECTED_FEATURES if f not in df.columns]
    if missing_feats:
        raise SystemExit(f"Validation failed: missing expected features: {missing_feats[:5]}")

    if not np.isfinite(df[EXPECTED_FEATURES + ['label']].to_numpy()).all():
        raise SystemExit('Validation failed: NaN or Inf detected')

    if len(df) >= 500:
        allowed_constant = {'yara_match_document', 'yara_match_ads'}
        constant = [c for c in EXPECTED_FEATURES if c not in allowed_constant and df[c].std(ddof=0) == 0]
        if constant:
            raise SystemExit(f"Validation failed: constant features detected: {constant[:5]}")

    computed_hash = hashlib.sha256("|".join(EXPECTED_FEATURES).encode('utf-8')).hexdigest()
    if computed_hash != FEATURE_LIST_HASH:
        raise SystemExit('Validation failed: feature list hash mismatch')

    monotonic_cols = ['files_created', 'files_modified', 'files_deleted', 'total_bytes_written', '_process_age_sec', '_events_seen']
    for pid, grp in df.sort_values(['pid', '_process_age_sec']).groupby('pid'):
        for col in monotonic_cols:
            if (grp[col].diff().dropna() < -1e-9).any():
                raise SystemExit(f'Validation failed: monotonicity violated for pid {pid} in {col}')
    
    class_balance = df['label'].value_counts().to_dict()
    snapshot_counts = df['_snapshot_phase'].value_counts().to_dict()
    return {
        'class_balance': class_balance,
        'snapshot_counts': snapshot_counts,
        'constant_features': [],
        'critical_constant_features': [],
    }


def generate(knobs: Knobs, seed: int, rows_target: int) -> Tuple[pd.DataFrame, List[MultiDimensionalLabel]]:
    random.seed(seed)
    np.random.seed(seed)

    rows: List[Dict[str, object]] = []
    multidim_labels: List[MultiDimensionalLabel] = []
    pid_val = 1000
    tree_counter = 0
    base_ts = time.time()
    
    # V3: Initialize engines
    adv_engine = AdversarialMutationEngine(AdversarialConfig(enable_ml_evasion=True, enable_mimicry=True)) if knobs.enable_adversarial else None
    lifecycle_sim = AttackLifecycleSimulator(seed=seed) if knobs.enable_attack_chain else None
    net_sim = AdvancedNetworkSimulator(seed=seed) if knobs.enable_advanced_network else None
    persist_gen = PersistenceMechanismGenerator(seed=seed) if knobs.enable_persistence else None
    
    while len(rows) < rows_target:
        label = 0 if random.random() < knobs.benign_ratio else 1
        
        tree_id = f'tree_{tree_counter}'
        tree = ProcessTree(tree_id, label, knobs, base_ts + random.uniform(0, 100))
        host, user = random.choice(HOSTS)
        base_tree_states = tree.build_tree(pid_val, host, user)
        tree_size = len(base_tree_states)
        
        for state in base_tree_states:
            state.host = host
            state.user = user
            
            # V3: Add adversarial technique
            if knobs.enable_adversarial and label == 1 and random.random() < knobs.adversarial_ratio:
                state.adversarial_technique = random.choice(knobs.adversarial_techniques)
            
            # V3: Add attack chain
            if knobs.enable_attack_chain and label == 1:
                state.attack_chain = lifecycle_sim.generate_attack_chain(label=label, family='generic')
            
            # V3: Add network profile
            if knobs.enable_advanced_network and label == 1:
                state.c2_profile = net_sim.generate_c2_profile(protocol=random.choice(['https', 'dns']))
            
            # V3: Add persistence
            if knobs.enable_persistence and label == 1:
                state.persistence_mechanisms = persist_gen.generate_persistence_set(label=label, count=random.randint(1, 3))
            
            for phase in SNAPSHOT_PHASES:
                short_features, meta = state.advance(phase)
                stage3_score, stage3_tier = _derive_stage3_score_and_tier(short_features)
                
                # V3: Apply adversarial mutations
                if state.adversarial_technique and adv_engine:
                    config = AdversarialConfig(enable_ml_evasion=True, mimicry_fidelity=0.85)
                    engine = AdversarialMutationEngine(config)
                    short_features = engine.apply_evasion(short_features, label=label, technique=state.adversarial_technique)
                
                cmdline = _generate_cmdline(state.image, state.label)
                yara_family = ''
                if short_features.get('yara_match_strength', 0) >= 2:
                    yara_family = random.choice(['crypto', 'packer', 'loader', 'ransomware'])
                
                record: Dict[str, object] = {
                    'event_uuid': str(uuid.uuid4()),
                    'ts_epoch': meta['ts_epoch'],
                    'host': meta['host'],
                    'pid': meta['pid'],
                    'ppid': meta['ppid'],
                    'image': state.image,
                    'command_line': cmdline,
                    'process_tree_id': state.tree_id,
                    'parent_image': state.parent_image,
                    'session_id': state.session_id,
                    'logon_type': state.logon_type,
                    'is_elevated': 1.0 if state.is_elevated else 0.0,
                    'uac_bypass_suspected': 1.0 if state.uac_bypass else 0.0,
                    'stage2_promoted': state.label == 1 or random.random() < 0.05,
                    'stage2_score': random.uniform(5, 15) if state.label == 1 else random.uniform(0, 8),
                    'stage3_score': stage3_score,
                    'stage3_tier': stage3_tier,
                    'yara_context': 'EXECUTABLE' if short_features.get('yara_match_executable') else 'NONE',
                    'yara_context_weight': short_features.get('yara_weighted_confidence', 0.0),
                    'yara_weighted_confidence': short_features.get('yara_weighted_confidence', 0.0),
                    'yara_boost': 0.0,
                    'yara_escalation_allowed': True,
                    'yara_family': yara_family,
                    'behavioral_signal_count': int(sum(1 for v in short_features.values() if isinstance(v, (int, float)) and v != 0)),
                    'yara_downweight_reason': '' if state.label == 1 else 'low_trust',
                    'label': state.label,
                    '_snapshot_phase': phase,
                    '_process_age_sec': meta['_process_age_sec'],
                    '_events_seen': meta['_events_seen'],
                    '_snapshot_method': 'fractional_time',
                    'files_created': state.cumulative['files_created'],
                    'files_modified': state.cumulative['files_modified'],
                    'files_deleted': state.cumulative['files_deleted'],
                    'total_bytes_written': state.cumulative['total_bytes_written'],
                    '_adversarial_technique': state.adversarial_technique or '',
                    '_attack_stage_count': len(state.attack_chain),
                    '_c2_protocol': state.c2_profile.get('protocol', ''),
                    '_persistence_count': len(state.persistence_mechanisms),
                }

                # Derive rate-based features to match runtime extractor (avoid constant-zero columns)
                age_sec = max(0.1, meta['_process_age_sec'])
                files_created_rate = state.cumulative['files_created'] / age_sec
                files_deleted_rate = state.cumulative['files_deleted'] / age_sec
                bytes_written_rate = state.cumulative['total_bytes_written'] / age_sec

                # Medium/long-term rates as smoothed variants with noise
                rate_noise = random.uniform(0.7, 1.3)
                medium_term_file_rate = (state.cumulative['files_modified'] / max(1.0, age_sec * 0.6)) * rate_noise
                long_term_file_rate = (state.cumulative['files_modified'] / max(1.0, age_sec * 1.5)) * random.uniform(0.6, 1.2)

                for key, value in {
                    'files_created_rate': files_created_rate,
                    'files_deleted_rate': files_deleted_rate,
                    'bytes_written_rate': bytes_written_rate,
                    'medium_term_file_rate': medium_term_file_rate,
                    'long_term_file_rate': long_term_file_rate,
                }.items():
                    if key not in short_features:
                        record[key] = float(value)

                # Entropy acceleration (not produced by generator by default)
                if 'entropy_acceleration' not in short_features:
                    entropy_velocity = short_features.get('entropy_velocity', 0.0)
                    entropy_acceleration = _bounded(entropy_velocity * random.uniform(0.1, 0.5) + random.uniform(-0.2, 0.2), 0.0, 2.5)
                    record['entropy_acceleration'] = float(entropy_acceleration)

                # Family/cross-PID features (simulate using tree size + label)
                if 'family_file_creates' not in short_features:
                    if label == 1:
                        family_file_creates = random.uniform(20, 80) * max(1, tree_size - 1)
                        family_file_deletes = random.uniform(10, 50) * max(1, tree_size - 1)
                        family_network_conns = random.uniform(5, 30) * max(1, tree_size - 1)
                        family_registry_mods = random.uniform(2, 20) * max(1, tree_size - 1)
                        family_entropy_avg = _bounded(short_features.get('entropy_trend', 6.0) + random.uniform(-0.5, 0.8), 0.0, 8.5)
                        family_suspicious_paths = random.uniform(0.3, 1.0) * max(1, tree_size - 1)
                    else:
                        family_file_creates = random.uniform(2, 20) * max(1, tree_size - 1)
                        family_file_deletes = random.uniform(1, 8) * max(1, tree_size - 1)
                        family_network_conns = random.uniform(1, 12) * max(1, tree_size - 1)
                        family_registry_mods = random.uniform(0, 5) * max(1, tree_size - 1)
                        family_entropy_avg = _bounded(short_features.get('entropy_trend', 3.5) + random.uniform(-0.5, 0.5), 0.0, 8.5)
                        family_suspicious_paths = random.uniform(0.0, 0.3) * max(1, tree_size - 1)

                    sibling_count = float(max(0, tree_size - 1))
                    family_file_rate = family_file_creates / max(1.0, age_sec)
                    family_network_rate = family_network_conns / max(1.0, age_sec)

                    record.update({
                        'family_file_creates': float(family_file_creates),
                        'family_file_deletes': float(family_file_deletes),
                        'family_network_conns': float(family_network_conns),
                        'family_registry_mods': float(family_registry_mods),
                        'sibling_count': float(sibling_count),
                        'family_entropy_avg': float(family_entropy_avg),
                        'family_suspicious_paths': float(family_suspicious_paths),
                        'family_file_rate': float(family_file_rate),
                        'family_network_rate': float(family_network_rate),
                    })

                # Network rate & burst features (runtime expects these)
                if 'network_connection_rate' not in short_features:
                    base_net = short_features.get('network_connections', 0.0)
                    network_connection_rate = (base_net / max(1.0, age_sec)) * random.uniform(0.7, 1.4)
                    record['network_connection_rate'] = float(network_connection_rate)

                if 'network_burst_60s' not in short_features:
                    if label == 1:
                        record['network_burst_60s'] = float(random.uniform(5, 35))
                    else:
                        record['network_burst_60s'] = float(random.uniform(0, 8))

                # Temporal spike windows
                if 'temporal_spikes_5min' not in short_features:
                    base_spike = short_features.get('temporal_correlation_spikes', 0.0)
                    record['temporal_spikes_5min'] = float(_bounded(base_spike * random.uniform(1.2, 3.0) + random.uniform(-1, 2), 0.0, 60.0))

                if 'temporal_spikes_30min' not in short_features:
                    base_spike = short_features.get('temporal_correlation_spikes', 0.0)
                    record['temporal_spikes_30min'] = float(_bounded(base_spike * random.uniform(2.0, 5.0) + random.uniform(-2, 5), 0.0, 120.0))

                # File event concentration (0..1)
                if 'file_event_concentration' not in short_features:
                    burstiness = short_features.get('file_io_acceleration', 0.0)
                    record['file_event_concentration'] = float(_bounded(1.0 / (1.0 + abs(burstiness)) + random.uniform(-0.05, 0.1), 0.0, 1.0))

                record.update(short_features)
                
                for key in ['command_line', 'image', 'host']:
                    _maybe_missing(record, key, knobs.p_noise_missing)
                
                rows.append(record)
                
                if random.random() < knobs.p_noise_duplicate:
                    dup = record.copy()
                    dup['event_uuid'] = str(uuid.uuid4())
                    rows.append(dup)
            
            # V3: Build multi-dimensional label
            if knobs.enable_multidim_labels and label == 1:
                md_label = generate_multidimensional_label(
                    pid=state.pid,
                    label=label,
                    attack_chain=state.attack_chain,
                    persistence=state.persistence_mechanisms,
                    base_ts=base_ts
                )
                multidim_labels.append(md_label)
        
        pid_val += len(base_tree_states) + random.randint(1, 3)
        tree_counter += 1
    
    df = pd.DataFrame(rows)
    
    if len(df) > rows_target:
        temp_df = df.head(rows_target)
        pids_included = temp_df['pid'].unique()
        df = df[df['pid'].isin(pids_included)].copy()
    
    while len(df) > rows_target:
        last_pid = df.iloc[-1]['pid']
        df = df[df['pid'] != last_pid].copy()

    # TASK 3: Post-generation validation - Check feature dominance
    dominance_report = check_feature_dominance(df, knobs)
    if dominance_report:
        print("\n" + "=" * 80)
        print("GENERATOR DOMINANCE REPORT")
        print("=" * 80)
        for item in dominance_report:
            print(f"Top Feature: {item['feature']} ({item['dominance']:.2%})")
            print(f"Status: {item['status']}")
            if item.get('recommendation'):
                print(f"Recommendation: {item['recommendation']}")
            print("-" * 80)
        print("=" * 80 + "\n")
    
    for col in EXPECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    object_cols = [c for c in df.columns if df[c].dtype == object]
    if object_cols:
        df[object_cols] = df[object_cols].fillna('')
    numeric_cols = [c for c in df.columns if c not in object_cols]
    if numeric_cols:
        df[numeric_cols] = df[numeric_cols].fillna(0)

    if object_cols:
        df[object_cols] = df[object_cols].astype(str)
    
    return df, multidim_labels


# ========================================================================================
# SECTION 14: UNIFIED EVENT PIPELINE
# ========================================================================================

SEVERITY_RANK = {'benign': 0, 'suspicious': 1, 'malicious': 2}
SEVERITY_TO_ID = {'benign': 0, 'suspicious': 1, 'malicious': 2}


def _stable_hash_int(value: str) -> int:
    return int(hashlib.sha256(value.encode('utf-8')).hexdigest()[:16], 16)


def _assign_split(seed: int, host_id: str, attack_scenario_id: str, split_policy: str) -> str:
    key = attack_scenario_id if split_policy == 'scenario' else host_id
    bucket = _stable_hash_int(f"{seed}:{key}") % 100
    if bucket < 70:
        return 'train'
    if bucket < 85:
        return 'val'
    return 'test'


def _label_from_row(row: pd.Series) -> str:
    # Use behavior-derived evidence only; avoid stage3_score shortcuts to reduce leakage.
    if int(row.get('label', 0)) == 0:
        suspicious_signal = (
            float(row.get('yara_weighted_confidence', 0.0)) > 0.55
            or float(row.get('file_extension_anomaly', 0.0)) > 4.0
            or float(row.get('parent_child_anomaly_score', 0.0)) > 0.55
            or float(row.get('excessive_crypt_apis', 0.0)) > 7.0
            or float(row.get('network_burst_60s', 0.0)) > 10.0
        )
        return 'suspicious' if suspicious_signal else 'benign'

    stealth_signal = (
        float(row.get('network_burst_60s', 0.0)) < 8.0
        or float(row.get('entropy_trend', 0.0)) < 6.8
        or float(row.get('excessive_crypt_apis', 0.0)) < 5.0
    )
    return 'suspicious' if stealth_signal else 'malicious'


def _max_label(labels: List[str]) -> str:
    if not labels:
        return 'benign'
    return max(labels, key=lambda x: SEVERITY_RANK.get(x, 0))


def _ensure_expected_features(df: pd.DataFrame) -> pd.DataFrame:
    for col in EXPECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0.0
    return df


def _build_timeline_metadata(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    timeline: Dict[str, Dict[str, float]] = {}
    for process_guid, grp in df.groupby('process_guid'):
        ts_min = float(grp['timestamp'].min())
        ts_max = float(grp['timestamp'].max())
        duration = max(1.0, ts_max - ts_min)
        process_label = _max_label(grp['process_label'].astype(str).tolist())

        if process_label == 'malicious':
            onset = ts_min + 0.60 * duration
        elif process_label == 'suspicious':
            onset = ts_min + 0.75 * duration
        else:
            onset = float('inf')

        timeline[process_guid] = {
            'min_ts': ts_min,
            'max_ts': ts_max,
            'onset_ts': onset,
        }
    return timeline


def _window_label(process_label: str, ts: float, onset_ts: float) -> str:
    if process_label == 'benign':
        return 'benign'
    if ts < onset_ts:
        return 'suspicious'
    return process_label


def _mitre_for_stage(stage: str) -> List[str]:
    mapping = {
        'initial_access': ['T1566.001', 'T1190'],
        'execution': ['T1059.001', 'T1204.002'],
        'file_activity': ['T1083', 'T1005'],
        'encryption_burst': ['T1486', 'T1490'],
        'exfiltration': ['T1041', 'T1048.003'],
        'impact': ['T1486', 'T1491'],
    }
    return mapping.get(stage, [])


# NEW: attack progression logic
def _attack_progression_state(phase: float) -> Tuple[str, float, float, float]:
    if phase <= 0.15:
        return 'initial_access', 0.35, 0.20, 0.15
    if phase <= 0.35:
        return 'execution', 0.60, 0.45, 0.35
    if phase <= 0.55:
        return 'file_activity', 1.00, 0.70, 0.85
    if phase <= 0.75:
        return 'encryption_burst', 1.55, 1.10, 1.60
    if phase <= 0.90:
        return 'exfiltration', 1.20, 1.65, 1.20
    return 'impact', 1.80, 1.35, 1.90


# NEW: feature correlation improvements
def _apply_event_feature_correlations(snapshot_event: Dict[str, object], process_label: str, phase: float, rng: random.Random) -> None:
    files_modified = float(snapshot_event.get('files_modified', 0.0) or 0.0)
    total_bytes_written = float(snapshot_event.get('total_bytes_written', 0.0) or 0.0)
    net_degree = float(snapshot_event.get('network_connections', 0.0) or 0.0)
    centrality = float(snapshot_event.get('network_connection_rate', 0.0) or 0.0)
    entropy = float(snapshot_event.get('entropy_trend', 0.0) or 0.0)
    crypt = float(snapshot_event.get('excessive_crypt_apis', 0.0) or 0.0)

    if total_bytes_written <= 0.0 or files_modified > 0.0:
        bytes_per_file = rng.uniform(80_000, 1_800_000)
        snapshot_event['total_bytes_written'] = (files_modified * bytes_per_file) * rng.uniform(0.75, 1.25)

    snapshot_event['network_connection_rate'] = max(
        float(snapshot_event.get('network_connection_rate', 0.0) or 0.0),
        net_degree * rng.uniform(0.35, 1.10) + rng.uniform(-2.0, 3.0),
    )
    snapshot_event['centrality_score'] = _bounded(
        (1.0 - np.exp(-max(0.0, net_degree) / 18.0)) * rng.uniform(0.8, 1.15), 0.0, 1.0
    )

    entropy_boost = (crypt * 0.06) + (float(snapshot_event.get('file_extension_anomaly', 0.0) or 0.0) * 0.02)
    if process_label in {'malicious', 'suspicious'}:
        entropy_boost += phase * rng.uniform(0.25, 0.65)
    snapshot_event['entropy_trend'] = _bounded(entropy + entropy_boost + rng.uniform(-0.15, 0.2), 0.0, 9.5)


# NEW: hard negative injection
def _inject_anomalous_behavior(window_features: Dict[str, object], rng: random.Random) -> None:
    """Inject benign-but-anomalous behavior to improve false-positive robustness."""
    # Backup-like write bursts
    window_features['files_modified'] = max(
        float(window_features.get('files_modified', 0.0) or 0.0),
        rng.uniform(40.0, 140.0),
    )
    window_features['total_bytes_written'] = max(
        float(window_features.get('total_bytes_written', 0.0) or 0.0),
        rng.uniform(80_000_000.0, 420_000_000.0),
    )
    # Moderate entropy spikes, not full ransomware profile
    window_features['entropy_trend'] = max(
        float(window_features.get('entropy_trend', 0.0) or 0.0),
        rng.uniform(5.2, 7.0),
    )
    window_features['entropy_velocity'] = max(
        float(window_features.get('entropy_velocity', 0.0) or 0.0),
        rng.uniform(0.05, 0.55),
    )
    # Update-like network load
    window_features['network_connections'] = max(
        float(window_features.get('network_connections', 0.0) or 0.0),
        rng.uniform(10.0, 30.0),
    )
    window_features['network_connection_rate'] = max(
        float(window_features.get('network_connection_rate', 0.0) or 0.0),
        rng.uniform(6.0, 20.0),
    )
    window_features['network_burst_60s'] = max(
        float(window_features.get('network_burst_60s', 0.0) or 0.0),
        rng.uniform(6.0, 18.0),
    )


# NEW: cross-process simulation
def _build_scenario_process_index(src: pd.DataFrame) -> Dict[str, List[Dict[str, object]]]:
    idx: Dict[str, List[Dict[str, object]]] = {}
    for _, r in src[['attack_scenario_id', 'process_guid', 'pid']].drop_duplicates().iterrows():
        sid = str(r['attack_scenario_id'])
        idx.setdefault(sid, []).append(
            {
                'process_guid': str(r['process_guid']),
                'pid': int(r['pid']),
            }
        )
    return idx


# NEW: event log generation
def generate_event_log(
    flat_df: pd.DataFrame,
    seed: int,
    split_policy: str = 'scenario',
    overlap_ratio: float = 0.05,
    evasion_ratio: float = 0.25,
    hard_negative_ratio: float = 0.10,
    missing_ratio: float = 0.01,
    outlier_ratio: float = 0.005,
    delay_ratio: float = 0.02,
    duplicate_ratio: float = 0.015,
    out_of_order_ratio: float = 0.03,
) -> pd.DataFrame:
    rng = random.Random(seed)
    np.random.seed(seed)

    src = flat_df.copy()
    src['host_id'] = src.get('host', '').astype(str)
    src['attack_scenario_id'] = src.get('process_tree_id', '').astype(str)
    src['process_guid'] = src.apply(
        lambda r: hashlib.sha1(
            f"{r.get('host_id','')}|{int(r.get('pid', 0))}|{r.get('attack_scenario_id','')}".encode('utf-8')
        ).hexdigest(),
        axis=1,
    )
    src['process_label'] = src.apply(_label_from_row, axis=1)
    src['split'] = src.apply(
        lambda r: _assign_split(
            seed=seed,
            host_id=str(r.get('host_id', '')),
            attack_scenario_id=str(r.get('attack_scenario_id', '')),
            split_policy=split_policy,
        ),
        axis=1,
    )

    timeline = _build_timeline_metadata(src.rename(columns={'ts_epoch': 'timestamp'}))
    scenario_index = _build_scenario_process_index(src)

    events: List[Dict[str, object]] = []
    for _, row in src.iterrows():
        process_guid = str(row['process_guid'])
        process_label = str(row['process_label'])
        ts = float(row.get('ts_epoch', time.time()))
        onset_ts = timeline[process_guid]['onset_ts']
        current_window_label = _window_label(process_label, ts, onset_ts)
        phase = float(row.get('_snapshot_phase', 0.0) or 0.0)
        progression_stage, file_mult, net_mult, burst_mult = _attack_progression_state(phase)

        # Overlap and evasion calibration
        if process_label == 'benign' and rng.random() < overlap_ratio:
            current_window_label = 'suspicious'
        if process_label == 'malicious' and rng.random() < evasion_ratio:
            if current_window_label == 'malicious':
                current_window_label = 'suspicious'

        common = {
            'timestamp': ts,
            'host_id': str(row.get('host_id', '')),
            'pid': int(row.get('pid', 0)),
            'process_guid': process_guid,
            'attack_scenario_id': str(row.get('attack_scenario_id', '')),
            'label_source': 'sim_ground_truth',
            'split': str(row.get('split', 'train')),
            'process_label': process_label,
            'window_label': current_window_label,
            'attack_stage': progression_stage,
            'mitre_techniques': json.dumps(_mitre_for_stage(progression_stage)),
            'is_ransomware': 1 if process_label in {'suspicious', 'malicious'} else 0,
            'evasion_type': str(row.get('_adversarial_technique', '') or 'none'),
            'event_uuid': str(uuid.uuid4()),
        }

        # Canonical feature snapshot event (single source of truth for derived datasets)
        snapshot_event: Dict[str, object] = dict(common)
        snapshot_event['event_type'] = 'feature_snapshot'
        snapshot_event['phase'] = phase
        for feat in EXPECTED_FEATURES:
            snapshot_event[feat] = float(row.get(feat, 0.0))

        # NEW: attack progression logic
        if process_label in {'suspicious', 'malicious'}:
            snapshot_event['files_modified'] = float(snapshot_event.get('files_modified', 0.0)) * file_mult
            snapshot_event['network_connection_rate'] = float(snapshot_event.get('network_connection_rate', 0.0)) * net_mult
            snapshot_event['network_burst_60s'] = float(snapshot_event.get('network_burst_60s', 0.0)) * burst_mult
            snapshot_event['temporal_spikes_5min'] = float(snapshot_event.get('temporal_spikes_5min', 0.0)) * burst_mult
            snapshot_event['temporal_spikes_30min'] = float(snapshot_event.get('temporal_spikes_30min', 0.0)) * max(1.0, burst_mult * 0.85)
            snapshot_event['entropy_trend'] = float(snapshot_event.get('entropy_trend', 0.0)) * (0.8 + 0.35 * phase)

        # NEW: feature correlation improvements
        _apply_event_feature_correlations(snapshot_event, process_label, phase, rng)

        # NEW: hard negative injection
        if current_window_label == 'benign' and rng.random() < hard_negative_ratio:
            _inject_anomalous_behavior(snapshot_event, rng)

        events.append(snapshot_event)

        # File write event
        file_evt = dict(common)
        file_evt.update(
            {
                'event_type': 'file_write',
                'bytes_written': float(row.get('total_bytes_written', 0.0)) / max(1.0, float(row.get('_events_seen', 1.0))),
                'entropy': float(row.get('entropy_trend', 0.0)),
                'files_modified': float(row.get('files_modified', 0.0)),
            }
        )
        events.append(file_evt)

        # Network connect event
        net_evt = dict(common)
        net_evt.update(
            {
                'event_type': 'network_connect',
                'connection_rate': float(snapshot_event.get('network_connection_rate', 0.0)),
                'network_degree': float(row.get('network_connections', 0.0)),
                'dst_port_risk': float(row.get('unexpected_ports_touched', 0.0)),
            }
        )
        events.append(net_evt)

        # Registry modification event (only if meaningful)
        reg_score = float(row.get('registry_modification_anomaly', 0.0))
        if reg_score > 0.1:
            reg_evt = dict(common)
            reg_evt.update(
                {
                    'event_type': 'registry_mod',
                    'registry_modification_anomaly': reg_score,
                }
            )
            events.append(reg_evt)

        # Process spawn event (if process has parent or spawn depth)
        spawn_depth = float(row.get('spawn_depth', 0.0))
        if spawn_depth > 0.0 or int(row.get('ppid', 0)) > 0:
            spawn_evt = dict(common)
            spawn_evt.update(
                {
                    'event_type': 'process_spawn',
                    'ppid': int(row.get('ppid', 0)),
                    'spawn_depth': spawn_depth,
                    'parent_child_anomaly_score': float(row.get('parent_child_anomaly_score', 0.0)),
                }
            )
            events.append(spawn_evt)

        # NEW: cross-process simulation
        scenario_nodes = scenario_index.get(str(row.get('attack_scenario_id', '')), [])
        if process_label in {'suspicious', 'malicious'} and len(scenario_nodes) > 1 and phase >= 0.45 and rng.random() < 0.35:
            peer = rng.choice([n for n in scenario_nodes if n['process_guid'] != process_guid])
            lateral_evt = dict(common)
            lateral_evt.update(
                {
                    'event_type': 'lateral_propagation',
                    'target_process_guid': str(peer['process_guid']),
                    'target_pid': int(peer['pid']),
                    'shared_file_activity': float(snapshot_event.get('files_modified', 0.0)) * rng.uniform(0.12, 0.35),
                    'shared_network_activity': float(snapshot_event.get('network_connection_rate', 0.0)) * rng.uniform(0.15, 0.45),
                }
            )
            events.append(lateral_evt)

    events_df = pd.DataFrame(events)
    events_df = _ensure_expected_features(events_df)

    # NEW: noise injection improvements
    # Missingness and outlier calibration on feature_snapshot events only
    snap_mask = events_df['event_type'] == 'feature_snapshot'
    feature_idx = events_df.index[snap_mask]
    for feat in EXPECTED_FEATURES:
        if feat not in events_df.columns:
            continue
        miss_count = int(len(feature_idx) * missing_ratio)
        out_count = int(len(feature_idx) * outlier_ratio)

        if miss_count > 0:
            miss_rows = np.random.choice(feature_idx.to_numpy(), size=min(miss_count, len(feature_idx)), replace=False)
            events_df.loc[miss_rows, feat] = np.nan

        if out_count > 0:
            out_rows = np.random.choice(feature_idx.to_numpy(), size=min(out_count, len(feature_idx)), replace=False)
            events_df.loc[out_rows, feat] = events_df.loc[out_rows, feat].astype(float) * np.random.uniform(2.0, 8.0, size=len(out_rows))

    # delayed events
    delayed_count = int(len(events_df) * max(0.0, min(1.0, delay_ratio)))
    if delayed_count > 0:
        delayed_rows = np.random.choice(events_df.index.to_numpy(), size=min(delayed_count, len(events_df)), replace=False)
        events_df.loc[delayed_rows, 'timestamp'] = events_df.loc[delayed_rows, 'timestamp'].astype(float) + np.random.uniform(8.0, 75.0, size=len(delayed_rows))

    # duplicate events
    dup_count = int(len(events_df) * max(0.0, min(1.0, duplicate_ratio)))
    if dup_count > 0:
        dup_rows = np.random.choice(events_df.index.to_numpy(), size=min(dup_count, len(events_df)), replace=False)
        dup_df = events_df.loc[dup_rows].copy()
        dup_df['event_uuid'] = [str(uuid.uuid4()) for _ in range(len(dup_df))]
        events_df = pd.concat([events_df, dup_df], ignore_index=True)

    # out-of-order timestamps on subset
    reorder_count = int(len(events_df) * max(0.0, min(1.0, out_of_order_ratio)))
    if reorder_count > 0:
        reorder_rows = np.random.choice(events_df.index.to_numpy(), size=min(reorder_count, len(events_df)), replace=False)
        events_df.loc[reorder_rows, 'timestamp'] = events_df.loc[reorder_rows, 'timestamp'].astype(float) - np.random.uniform(2.0, 30.0, size=len(reorder_rows))

    events_df.sort_values(['timestamp', 'process_guid', 'event_type'], inplace=True)
    events_df.reset_index(drop=True, inplace=True)
    return events_df


# NEW: stage3 aggregation
def _aggregate_window_label(
    labels: List[str],
    policy: str,
    suspicious_min_ratio: float,
    malicious_min_ratio: float,
) -> str:
    if not labels:
        return 'benign'

    if policy == 'max':
        return _max_label(labels)

    # NEW: ratio-based window labeling
    total = float(len(labels))
    malicious_count = float(sum(1 for x in labels if x == 'malicious'))
    suspicious_count = float(sum(1 for x in labels if x == 'suspicious'))

    if (malicious_count / total) >= malicious_min_ratio:
        return 'malicious'
    if (suspicious_count / total) >= suspicious_min_ratio:
        return 'suspicious'
    return 'benign'


def _stage3_split_positive_ratios(stage3_df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    report: Dict[str, Dict[str, float]] = {}
    for split_name in ['train', 'val', 'test']:
        part = stage3_df[stage3_df['split'] == split_name]
        total = int(len(part))
        pos = int((part['label'] > 0).sum()) if total > 0 else 0
        report[split_name] = {
            'rows': total,
            'positive_rows': pos,
            'positive_ratio': float(pos / total) if total > 0 else 0.0,
        }
    return report


def rebalance_by_process_groups(
    df: pd.DataFrame,
    target_positive_ratio: float,
    seed: int,
    max_change_ratio: float = 0.80,
    tolerance: float = 0.02,
) -> Tuple[pd.DataFrame, Dict[str, object]]:
    """# NEW: group-based rebalancing"""
    rng = random.Random(seed)
    target = max(0.01, min(0.99, float(target_positive_ratio)))
    max_change = max(0.05, min(0.95, float(max_change_ratio)))
    tol = max(0.0, float(tolerance))

    if df.empty:
        return df, {'status': 'empty'}

    work = df.copy()
    work['is_positive'] = (work['label'] > 0).astype(int)
    proc_stats = work.groupby('process_guid', as_index=True).agg(
        rows=('label', 'size'),
        pos_rows=('is_positive', 'sum'),
    )
    proc_stats['is_positive_process'] = (proc_stats['pos_rows'] > 0).astype(int)

    total_rows = int(len(work))
    pos_rows = int(work['is_positive'].sum())
    current_ratio = float(pos_rows / max(1, total_rows))
    max_rows_to_remove = int(total_rows * max_change)

    removed_guids: Set[str] = set()
    removed_rows = 0
    removed_pos_rows = 0

    def _ratio_after(remove_rows: int, remove_pos_rows: int) -> float:
        new_total = total_rows - remove_rows
        new_pos = pos_rows - remove_pos_rows
        if new_total <= 0:
            return current_ratio
        return float(new_pos / new_total)

    if current_ratio > (target + tol):
        candidates = proc_stats[proc_stats['is_positive_process'] == 1].index.tolist()
        rng.shuffle(candidates)
        candidates.sort(
            key=lambda g: (
                -float(proc_stats.loc[g, 'pos_rows']) / max(1.0, float(proc_stats.loc[g, 'rows'])),
                int(proc_stats.loc[g, 'rows']),
            )
        )
        for guid in candidates:
            guid_rows = int(proc_stats.loc[guid, 'rows'])
            guid_pos = int(proc_stats.loc[guid, 'pos_rows'])
            if removed_rows + guid_rows > max_rows_to_remove:
                continue

            new_total = total_rows - (removed_rows + guid_rows)
            new_pos = pos_rows - (removed_pos_rows + guid_pos)
            if new_total <= 0:
                continue
            new_ratio = float(new_pos / new_total)

            if abs(new_ratio - target) < abs(current_ratio - target):
                removed_guids.add(str(guid))
                removed_rows += guid_rows
                removed_pos_rows += guid_pos
                current_ratio = new_ratio
            if current_ratio <= (target + tol):
                break
    elif current_ratio < (target - tol):
        candidates = proc_stats[proc_stats['is_positive_process'] == 0].index.tolist()
        rng.shuffle(candidates)
        candidates.sort(key=lambda g: int(proc_stats.loc[g, 'rows']))
        for guid in candidates:
            guid_rows = int(proc_stats.loc[guid, 'rows'])
            if removed_rows + guid_rows > max_rows_to_remove:
                continue

            new_total = total_rows - (removed_rows + guid_rows)
            new_pos = pos_rows - removed_pos_rows
            if new_total <= 0:
                continue
            new_ratio = float(new_pos / new_total)

            if abs(new_ratio - target) < abs(current_ratio - target):
                removed_guids.add(str(guid))
                removed_rows += guid_rows
                current_ratio = new_ratio
            if current_ratio >= (target - tol):
                break

    # Stochastic refinement to better match targets when greedy gets stuck on group granularity.
    need_refine = abs(current_ratio - target) > tol
    if need_refine:
        if current_ratio > target:
            candidate_df = proc_stats[proc_stats['is_positive_process'] == 1]
        else:
            candidate_df = proc_stats[proc_stats['is_positive_process'] == 0]

        candidate_rows = [
            (
                str(guid),
                int(candidate_df.loc[guid, 'rows']),
                int(candidate_df.loc[guid, 'pos_rows']),
            )
            for guid in candidate_df.index.tolist()
        ]

        best_guids = set(removed_guids)
        best_rows = removed_rows
        best_pos_rows = removed_pos_rows
        best_ratio = _ratio_after(best_rows, best_pos_rows)
        best_distance = abs(best_ratio - target)

        for _ in range(400):
            trial_guids: Set[str] = set()
            trial_rows = 0
            trial_pos_rows = 0
            shuffled = candidate_rows[:]
            rng.shuffle(shuffled)

            for guid, g_rows, g_pos in shuffled:
                if trial_rows + g_rows > max_rows_to_remove:
                    continue
                new_rows = trial_rows + g_rows
                new_pos_rows = trial_pos_rows + g_pos
                ratio = _ratio_after(new_rows, new_pos_rows)
                # Keep moves that do not diverge too far while exploring combinations.
                if abs(ratio - target) <= (best_distance + 0.02):
                    trial_guids.add(guid)
                    trial_rows = new_rows
                    trial_pos_rows = new_pos_rows

            trial_ratio = _ratio_after(trial_rows, trial_pos_rows)
            trial_distance = abs(trial_ratio - target)
            if trial_distance < best_distance:
                best_distance = trial_distance
                best_ratio = trial_ratio
                best_guids = trial_guids
                best_rows = trial_rows
                best_pos_rows = trial_pos_rows
                if best_distance <= tol:
                    break

        if best_distance < abs(current_ratio - target):
            removed_guids = best_guids
            removed_rows = best_rows
            removed_pos_rows = best_pos_rows
            current_ratio = best_ratio

    kept = work[~work['process_guid'].astype(str).isin(removed_guids)].copy()
    kept.drop(columns=['is_positive'], inplace=True, errors='ignore')
    kept.reset_index(drop=True, inplace=True)

    final_total = int(len(kept))
    final_pos = int((kept['label'] > 0).sum()) if final_total > 0 else 0
    summary = {
        'status': 'ok',
        'target_positive_ratio': target,
        'before_rows': total_rows,
        'before_positive_ratio': float(pos_rows / max(1, total_rows)),
        'after_rows': final_total,
        'after_positive_ratio': float(final_pos / max(1, final_total)),
        'removed_processes': int(len(removed_guids)),
        'removed_rows': int(removed_rows),
        'max_change_ratio': max_change,
        'tolerance': tol,
    }
    return kept, summary


def rebalance_stage3_by_process(
    stage3_df: pd.DataFrame,
    target_positive_ratios: Dict[str, float],
    max_change_ratio: float = 0.80,
    tolerance: float = 0.02,
    seed: int = 42,
) -> Tuple[pd.DataFrame, Dict[str, object]]:
    """Rebalance Stage 3 windows by dropping entire process groups per split.

    This preserves process isolation and avoids leakage from partial process slicing.
    """
    summary: Dict[str, object] = {
        'target_positive_ratios': {
            'train': float(target_positive_ratios.get('train', 0.40)),
            'val': float(target_positive_ratios.get('val', 0.35)),
            'test': float(target_positive_ratios.get('test', 0.15)),
        },
        'max_change_ratio': float(max_change_ratio),
        'tolerance': float(tolerance),
        'splits': {},
    }

    kept_parts: List[pd.DataFrame] = []
    for split_name in ['train', 'val', 'test']:
        split_df = stage3_df[stage3_df['split'] == split_name].copy()
        if split_df.empty:
            summary['splits'][split_name] = {'status': 'empty'}
            continue
        target = float(target_positive_ratios.get(split_name, 0.40))
        kept, split_summary = rebalance_by_process_groups(
            split_df,
            target_positive_ratio=target,
            seed=seed + {'train': 0, 'val': 101, 'test': 202}[split_name],
            max_change_ratio=max_change_ratio,
            tolerance=tolerance,
        )
        kept_parts.append(kept)
        summary['splits'][split_name] = split_summary

    if not kept_parts:
        return stage3_df, summary

    out = pd.concat(kept_parts, ignore_index=True)
    out.sort_values(['split', 'process_guid', 'window_index'], inplace=True)
    out.reset_index(drop=True, inplace=True)
    return out, summary


def build_stage3_dataset(
    events_df: pd.DataFrame,
    window_sec: int = 120,
    window_label_policy: str = 'ratio',
    suspicious_min_ratio: float = 0.45,
    malicious_min_ratio: float = 0.35,
) -> pd.DataFrame:
    snap = events_df[events_df['event_type'] == 'feature_snapshot'].copy()
    if snap.empty:
        return pd.DataFrame()

    snap['timestamp'] = snap['timestamp'].astype(float)
    min_ts = snap.groupby('process_guid')['timestamp'].transform('min')
    snap['window_index'] = ((snap['timestamp'] - min_ts) // float(window_sec)).astype(int)
    snap['window_start_ts'] = min_ts + snap['window_index'] * float(window_sec)

    agg_cols = {
        **{f: 'mean' for f in EXPECTED_FEATURES},
        'timestamp': 'max',
        'window_start_ts': 'min',
        'host_id': 'first',
        'pid': 'first',
        'attack_scenario_id': 'first',
        'label_source': 'first',
        'split': 'first',
        'attack_stage': 'last',
        'mitre_techniques': 'last',
        'is_ransomware': 'max',
        'evasion_type': 'last',
    }

    grouped = snap.groupby(['process_guid', 'window_index'], as_index=False).agg(agg_cols)

    # Window-level label supports max or ratio policies.
    label_window = (
        snap.groupby(['process_guid', 'window_index'])['window_label']
        .apply(
            lambda s: _aggregate_window_label(
                [str(x) for x in s],
                policy=window_label_policy,
                suspicious_min_ratio=max(0.0, min(1.0, suspicious_min_ratio)),
                malicious_min_ratio=max(0.0, min(1.0, malicious_min_ratio)),
            )
        )
        .reset_index(name='label_name')
    )
    grouped = grouped.merge(label_window, on=['process_guid', 'window_index'], how='left')
    grouped['label'] = grouped['label_name'].map(SEVERITY_TO_ID).fillna(0).astype(int)

    grouped['timestamp'] = grouped['timestamp'].astype(float)
    grouped['window_start_ts'] = grouped['window_start_ts'].astype(float)
    grouped['is_ransomware'] = grouped['is_ransomware'].fillna(0).astype(int)
    grouped = _ensure_expected_features(grouped)
    return grouped


# NEW: stage4 sequence builder
def build_stage4_sequences(stage3_df: pd.DataFrame, sequence_length: int = 8, stride: int = 2) -> pd.DataFrame:
    if stage3_df.empty:
        return pd.DataFrame()

    seq_rows: List[Dict[str, object]] = []
    for process_guid, grp in stage3_df.sort_values(['process_guid', 'window_index']).groupby('process_guid'):
        rows = grp.reset_index(drop=True)
        n = len(rows)
        if n == 0:
            continue

        for start in range(0, max(1, n), max(1, stride)):
            end = start + sequence_length
            window = rows.iloc[start:end]
            if len(window) == 0:
                continue

            seq_base = window[EXPECTED_FEATURES].fillna(0.0).astype(float).reset_index(drop=True)

            # NEW: temporal feature engineering
            seq_enriched: List[Dict[str, float]] = []
            prev = None
            entropy_roll: List[float] = []
            for t in range(len(seq_base)):
                current = seq_base.iloc[t].to_dict()
                entropy_roll.append(float(current.get('entropy_trend', 0.0) or 0.0))

                if prev is None:
                    delta_files_modified = 0.0
                    delta_entropy = 0.0
                    io_rate_change = 0.0
                    burst_growth_rate = 0.0
                else:
                    delta_files_modified = float(current.get('files_modified', 0.0)) - float(prev.get('files_modified', 0.0))
                    delta_entropy = float(current.get('entropy_trend', 0.0)) - float(prev.get('entropy_trend', 0.0))
                    prev_bytes = max(1.0, float(prev.get('total_bytes_written', 0.0)))
                    io_rate_change = (float(current.get('total_bytes_written', 0.0)) - float(prev.get('total_bytes_written', 0.0))) / prev_bytes
                    prev_burst = max(1.0, float(prev.get('temporal_spikes_5min', 0.0)))
                    burst_growth_rate = (float(current.get('temporal_spikes_5min', 0.0)) - float(prev.get('temporal_spikes_5min', 0.0))) / prev_burst

                rolling_entropy_avg = float(np.mean(entropy_roll[-3:]))
                current.update(
                    {
                        'delta_files_modified': float(delta_files_modified),
                        'delta_entropy': float(delta_entropy),
                        'io_rate_change': float(io_rate_change),
                        'rolling_entropy_avg': float(rolling_entropy_avg),
                        'burst_growth_rate': float(burst_growth_rate),
                    }
                )
                seq_enriched.append(current)
                prev = current

            seq_feats = seq_enriched
            mask = [1] * len(seq_feats)

            # NEW: sequence padding/truncation
            pad_needed = max(0, sequence_length - len(seq_feats))
            if pad_needed > 0:
                pad_template = {f: 0.0 for f in EXPECTED_FEATURES}
                pad_template.update(
                    {
                        'delta_files_modified': 0.0,
                        'delta_entropy': 0.0,
                        'io_rate_change': 0.0,
                        'rolling_entropy_avg': 0.0,
                        'burst_growth_rate': 0.0,
                    }
                )
                seq_feats.extend([dict(pad_template) for _ in range(pad_needed)])
                mask.extend([0] * pad_needed)
            elif len(seq_feats) > sequence_length:
                seq_feats = seq_feats[-sequence_length:]
                mask = [1] * sequence_length

            label_name = str(window.iloc[-1]['label_name'])
            seq_rows.append(
                {
                    'sequence_id': str(uuid.uuid4()),
                    'process_guid': str(process_guid),
                    'host_id': str(window.iloc[-1]['host_id']),
                    'attack_scenario_id': str(window.iloc[-1]['attack_scenario_id']),
                    'label_source': str(window.iloc[-1]['label_source']),
                    'split': str(window.iloc[-1]['split']),
                    'sequence_length': int(sequence_length),
                    'sequence_stride': int(stride),
                    'effective_length': int(len(window)),
                    'window_start_index': int(start),
                    'window_end_index': int(min(end - 1, n - 1)),
                    'label_name': label_name,
                    'label': int(SEVERITY_TO_ID.get(label_name, 0)),
                    # NEW: multi-task labels
                    'attack_stage': str(window.iloc[-1].get('attack_stage', 'unknown')),
                    'mitre_techniques': str(window.iloc[-1].get('mitre_techniques', '[]')),
                    'is_ransomware': int(window.iloc[-1].get('is_ransomware', 0)),
                    'evasion_type': str(window.iloc[-1].get('evasion_type', 'none')),
                    'sequence_features': json.dumps(seq_feats),
                    'sequence_mask': json.dumps(mask),
                }
            )

            if end >= n:
                break

    return pd.DataFrame(seq_rows)


def compute_data_quality(events_df: pd.DataFrame, stage3_df: pd.DataFrame, stage4_df: pd.DataFrame) -> Dict[str, object]:
    snapshot = events_df[events_df['event_type'] == 'feature_snapshot'].copy()
    missing_pct = float(snapshot[EXPECTED_FEATURES].isna().mean().mean() * 100.0) if not snapshot.empty else 0.0

    corr_files_bytes = float('nan')
    corr_net_cent = float('nan')
    corr_temporal = float('nan')
    if not stage3_df.empty:
        safe = stage3_df[EXPECTED_FEATURES].fillna(0.0)
        if {'files_modified', 'total_bytes_written'}.issubset(safe.columns):
            corr_files_bytes = float(safe[['files_modified', 'total_bytes_written']].corr().iloc[0, 1])
        if {'network_connections', 'network_connection_rate'}.issubset(safe.columns):
            corr_net_cent = float(safe[['network_connections', 'network_connection_rate']].corr().iloc[0, 1])
        if {'temporal_spikes_5min', 'file_io_acceleration'}.issubset(safe.columns):
            corr_temporal = float(safe[['temporal_spikes_5min', 'file_io_acceleration']].corr().iloc[0, 1])

    return {
        'rows': {
            'raw_events': int(len(events_df)),
            'stage3_dataset': int(len(stage3_df)),
            'stage4_sequences': int(len(stage4_df)),
        },
        'label_counts': {
            'events': events_df['window_label'].value_counts(dropna=False).to_dict() if 'window_label' in events_df.columns else {},
            'stage3': stage3_df['label_name'].value_counts(dropna=False).to_dict() if 'label_name' in stage3_df.columns else {},
            'stage4': stage4_df['label_name'].value_counts(dropna=False).to_dict() if 'label_name' in stage4_df.columns else {},
        },
        'split_counts': {
            'events': events_df['split'].value_counts(dropna=False).to_dict() if 'split' in events_df.columns else {},
            'stage3': stage3_df['split'].value_counts(dropna=False).to_dict() if 'split' in stage3_df.columns else {},
            'stage4': stage4_df['split'].value_counts(dropna=False).to_dict() if 'split' in stage4_df.columns else {},
        },
        'missingness_percent': {
            'feature_snapshot': missing_pct,
        },
        'correlations': {
            'files_modified_vs_total_bytes_written': corr_files_bytes,
            'network_connections_vs_network_connection_rate': corr_net_cent,
            'temporal_spikes_5min_vs_file_io_acceleration': corr_temporal,
        },
        'consistency': {
            'stage3_stage4_process_overlap': float(
                len(set(stage3_df.get('process_guid', pd.Series(dtype=str)).astype(str).unique())
                    & set(stage4_df.get('process_guid', pd.Series(dtype=str)).astype(str).unique()))
                / max(1, len(set(stage3_df.get('process_guid', pd.Series(dtype=str)).astype(str).unique())))
            ),
            'label_alignment_rate': float(
                stage4_df.merge(
                    stage3_df[['process_guid', 'label_name']].drop_duplicates(subset=['process_guid']),
                    on='process_guid',
                    how='left',
                    suffixes=('_s4', '_s3')
                ).assign(match=lambda d: d['label_name_s4'] == d['label_name_s3'])['match'].mean()
            ) if (not stage3_df.empty and not stage4_df.empty) else 1.0,
        },
    }


def build_file_contracts() -> Dict[str, object]:
    return {
        'raw_events.parquet': {
            'required_columns': [
                'timestamp', 'host_id', 'pid', 'process_guid', 'attack_scenario_id',
                'event_type', 'label_source', 'split', 'process_label', 'window_label',
            ],
            'feature_columns': EXPECTED_FEATURES,
        },
        'stage3_dataset.parquet': {
            'required_columns': [
                'process_guid', 'window_index', 'window_start_ts', 'host_id',
                'attack_scenario_id', 'label_source', 'split', 'label_name', 'label',
            ],
            'feature_columns': EXPECTED_FEATURES,
        },
        'stage4_sequences.parquet': {
            'required_columns': [
                'sequence_id', 'process_guid', 'host_id', 'attack_scenario_id',
                'label_source', 'split', 'sequence_length', 'sequence_stride',
                'effective_length', 'label_name', 'label', 'attack_stage', 'mitre_techniques',
                'is_ransomware', 'evasion_type', 'sequence_features', 'sequence_mask',
            ],
            'feature_contract': {
                'fixed_sequence_length': 'sequence_length',
                'stride': 'sequence_stride',
                'padding': 'zero-padding for missing timesteps',
                'mask': 'sequence_mask (1=real timestep, 0=padding)',
            },
        },
    }


# ========================================================================================
# SECTION 14: PERSISTENCE & OUTPUT
# ========================================================================================

def build_output_path(out_arg: str) -> Path:
    if out_arg:
        return Path(out_arg)
    date_str = datetime.now().strftime('%Y%m%d')
    return Path(f"data/fyp_dataset_v1_realistic_{date_str}.parquet")


def feature_stats(df: pd.DataFrame) -> Dict[str, object]:
    stats = {}
    for col in EXPECTED_FEATURES:
        series = df[col]
        stats[col] = {
            'min': float(series.min()),
            'max': float(series.max()),
            'mean': float(series.mean()),
            'std': float(series.std(ddof=0)),
        }
    return stats


def save_outputs(df: pd.DataFrame, out_path: Path, knobs: Knobs, seed: int, validation: Dict[str, object], md_labels: List[MultiDimensionalLabel]) -> None:
    if 'host' in df.columns:
        df['host'] = df['host'].astype(str)
    if 'image' in df.columns:
        df['image'] = df['image'].astype(str)
    if 'command_line' in df.columns:
        df['command_line'] = df['command_line'].astype(str)
    if 'parent_image' in df.columns:
        df['parent_image'] = df['parent_image'].astype(str)

    table = pa.Table.from_pandas(df)
    meta = {
        'schema_version': SCHEMA_VERSION,
        'feature_list_hash': FEATURE_LIST_HASH,
        'generator_mode': 'realistic_v4',
        'seed': str(seed),
        'knobs': json.dumps(asdict(knobs)),
        'rows': str(len(df)),
        'class_balance': json.dumps(validation['class_balance']),
        'snapshot_counts': json.dumps(validation['snapshot_counts']),
    }
    existing = table.schema.metadata or {}
    meta_bytes = {k.encode(): v.encode() for k, v in meta.items()}
    full_meta = existing.copy()
    full_meta.update(meta_bytes)
    table = table.replace_schema_metadata(full_meta)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, out_path, compression="zstd")

    sidecar = {
        'schema_version': SCHEMA_VERSION,
        'feature_list_hash': FEATURE_LIST_HASH,
        'generator_mode': 'realistic_v4',
        'seed': seed,
        'knobs': asdict(knobs),
        'rows': len(df),
        'class_balance': validation['class_balance'],
        'snapshot_counts': validation['snapshot_counts'],
        'feature_stats': feature_stats(df),
    }
    sidecar_path = out_path.with_suffix('.config.json')
    sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding='utf-8')
    
    # Save multi-dimensional labels
    if md_labels:
        labels_path = out_path.with_stem(out_path.stem + '.multidim_labels')
        labels_path = labels_path.with_suffix('.json')
        with open(labels_path, 'w', encoding='utf-8') as f:
            json.dump([lbl.to_dict() for lbl in md_labels], f, indent=2)


# ========================================================================================
# SECTION 15: CLI
# ========================================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Complete EDR Dataset Generator v4 - All-in-one with adversarial capabilities")
    
    # Base arguments
    p.add_argument('--out', default='', help='Output parquet path')
    p.add_argument('--rows', type=int, default=5000, help='Total rows')
    p.add_argument('--benign-ratio', type=float, default=0.90, help='Benign fraction (default: 0.90)')
    p.add_argument('--seed', type=int, default=42, help='Random seed')
    
    # V4 feature flags
    p.add_argument('--enable-adversarial', action='store_true', help='Enable adversarial perturbations')
    p.add_argument('--enable-attack-chain', action='store_true', help='Enable attack lifecycle')
    p.add_argument('--enable-advanced-network', action='store_true', help='Enable advanced network')
    p.add_argument('--enable-persistence', action='store_true', help='Enable persistence mechanisms')
    p.add_argument('--enable-multidim-labels', action='store_true', help='Enable multi-dimensional labels')
    p.add_argument('--enable-all-v4', action='store_true', help='Enable all v4 features')
    p.add_argument('--enable-all-v3', action='store_true', help='Enable all v3 features')
    
    # Adversarial parameters
    p.add_argument('--adversarial-ratio', type=float, default=0.2, help='Fraction of ransomware using evasion')
    p.add_argument('--adversarial-technique', default='random', 
                   choices=['random', 'fgsm', 'mimicry_backup', 'mimicry_compression', 'causality_preserving'],
                   help='Adversarial technique')

    # Unified pipeline outputs
    p.add_argument('--output-events', action='store_true', help='Write raw event logs parquet')
    p.add_argument('--output-stage3', action='store_true', help='Write Stage 3 aggregated dataset parquet')
    p.add_argument('--output-stage4', action='store_true', help='Write Stage 4 temporal sequence dataset parquet')
    p.add_argument('--output-dir', default='data', help='Output directory for unified pipeline artifacts')

    # Leakage-safe split policy
    p.add_argument('--split-policy', default='scenario', choices=['scenario', 'host'],
                   help='Split assignment key for leakage-safe partitioning')

    # Stage 3/4 derivation settings
    p.add_argument('--stage3-window-sec', type=int, default=120, help='Aggregation window size in seconds for Stage 3')
    p.add_argument('--stage3-window-label-policy', default='ratio', choices=['max', 'ratio'],
                   help='Stage 3 window label policy: max severity or ratio-based')
    p.add_argument('--malicious-threshold', type=float, default=0.35,
                   help='Min malicious fraction per window for malicious label')
    p.add_argument('--suspicious-threshold', type=float, default=0.30,
                   help='Min suspicious fraction per window for suspicious label')
    p.add_argument('--target-positive-train', type=float, default=0.40,
                   help='Target Stage 3 positive ratio for train split')
    p.add_argument('--target-positive-val', type=float, default=0.35,
                   help='Target Stage 3 positive ratio for validation split')
    p.add_argument('--target-positive-test', type=float, default=0.15,
                   help='Target Stage 3 positive ratio for test split')
    p.add_argument('--stage3-rebalance-max-change', type=float, default=0.80,
                   help='Max fraction of Stage 3 rows removable per split during rebalance')
    # Backward-compatible aliases
    p.add_argument('--stage3-suspicious-min-ratio', type=float, default=None,
                   help=argparse.SUPPRESS)
    p.add_argument('--stage3-malicious-min-ratio', type=float, default=None,
                   help=argparse.SUPPRESS)
    p.add_argument('--target-stage3-positive-ratio', type=float, default=None,
                   help=argparse.SUPPRESS)
    p.add_argument('--stage4-seq-len', type=int, default=None, help='Fixed sequence length for Stage 4 (legacy flag)')
    p.add_argument('--sequence-length', type=int, default=20, help='Fixed sequence length for Stage 4 sequences')
    p.add_argument('--stage4-stride', type=int, default=2, help='Sliding stride for Stage 4 sequence builder')

    # Calibration controls
    p.add_argument('--overlap-ratio', type=float, default=0.05, help='Class overlap ratio for benign->suspicious bleed')
    p.add_argument('--evasion-ratio', type=float, default=0.25, help='Malicious evasion ratio for suspicious-like behavior')
    p.add_argument('--hard-negative-ratio', type=float, default=0.10, help='Benign anomalous window injection ratio')
    p.add_argument('--missing-rate', type=float, default=0.01, help='Feature missingness ratio in raw events')
    p.add_argument('--outlier-rate', type=float, default=0.005, help='Feature outlier injection ratio in raw events')
    p.add_argument('--delay-rate', type=float, default=0.02, help='Delayed event ratio in raw events')
    p.add_argument('--duplicate-rate', type=float, default=0.015, help='Duplicate event ratio in raw events')
    p.add_argument('--out-of-order-rate', type=float, default=0.03, help='Out-of-order timestamp ratio in raw events')
    p.add_argument('--class-profile', default='balanced', choices=['balanced', 'soc'],
                   help='Class profile preset: balanced uses benign-ratio, soc enforces SOC-like imbalance')
    
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Backward-compatible argument mapping
    if args.stage3_malicious_min_ratio is not None:
        args.malicious_threshold = args.stage3_malicious_min_ratio
    if args.stage3_suspicious_min_ratio is not None:
        args.suspicious_threshold = args.stage3_suspicious_min_ratio
    if args.target_stage3_positive_ratio is not None:
        args.target_positive_train = args.target_stage3_positive_ratio
        args.target_positive_val = args.target_stage3_positive_ratio
        args.target_positive_test = args.target_stage3_positive_ratio
    
    if args.enable_all_v3 or args.enable_all_v4:
        args.enable_adversarial = True
        args.enable_attack_chain = True
        args.enable_advanced_network = True
        args.enable_persistence = True
        args.enable_multidim_labels = True
    
    if args.class_profile == 'soc':
        args.benign_ratio = max(args.benign_ratio, 0.94)

    if args.out:
        out_path = Path(args.out)
    else:
        suffix = '_v4' if any([args.enable_adversarial, args.enable_attack_chain, args.enable_advanced_network]) else ''
        date_str = datetime.now().strftime('%Y%m%d')
        out_path = Path(f"data/fyp_dataset{suffix}_realistic_{date_str}.parquet")

    write_events = args.output_events
    write_stage3 = args.output_stage3
    write_stage4 = args.output_stage4
    if not (write_events or write_stage3 or write_stage4):
        # Default to writing full unified pipeline when no explicit mode is provided.
        write_events = True
        write_stage3 = True
        write_stage4 = True
    
    adv_techniques = ['fgsm', 'mimicry_backup', 'mimicry_compression', 'causality_preserving'] if args.adversarial_technique == 'random' else [args.adversarial_technique]
    
    knobs = Knobs(
        benign_ratio=args.benign_ratio,
        target_rows=args.rows,
        enable_adversarial=args.enable_adversarial,
        enable_attack_chain=args.enable_attack_chain,
        enable_advanced_network=args.enable_advanced_network,
        enable_persistence=args.enable_persistence,
        enable_multidim_labels=args.enable_multidim_labels,
        adversarial_ratio=args.adversarial_ratio,
        adversarial_techniques=adv_techniques,
    )
    
    print(f"Generating dataset with:")
    print(f"  Rows: {args.rows:,}")
    print(f"  Benign ratio: {args.benign_ratio:.1%}")
    print(f"  Adversarial: {args.enable_adversarial}")
    print(f"  Attack chain: {args.enable_attack_chain}")
    print(f"  Advanced network: {args.enable_advanced_network}")
    print(f"  Persistence: {args.enable_persistence}")
    print(f"  Multi-dim labels: {args.enable_multidim_labels}")
    print(f"  Unified outputs: events={write_events}, stage3={write_stage3}, stage4={write_stage4}")
    print()
    
    df, md_labels = generate(knobs, seed=args.seed, rows_target=args.rows)
    validation = validate_df(df)
    save_outputs(df, out_path, knobs, seed=args.seed, validation=validation, md_labels=md_labels)

    # Build unified event-ground-truth and derived Stage 3/Stage 4 datasets.
    seq_len = int(args.stage4_seq_len) if args.stage4_seq_len is not None else int(args.sequence_length)

    events_df = generate_event_log(
        flat_df=df,
        seed=args.seed,
        split_policy=args.split_policy,
        overlap_ratio=max(0.0, min(1.0, args.overlap_ratio)),
        evasion_ratio=max(0.0, min(1.0, args.evasion_ratio)),
        hard_negative_ratio=max(0.0, min(1.0, args.hard_negative_ratio)),
        missing_ratio=max(0.0, min(1.0, args.missing_rate)),
        outlier_ratio=max(0.0, min(1.0, args.outlier_rate)),
        delay_ratio=max(0.0, min(1.0, args.delay_rate)),
        duplicate_ratio=max(0.0, min(1.0, args.duplicate_rate)),
        out_of_order_ratio=max(0.0, min(1.0, args.out_of_order_rate)),
    )
    stage3_df = build_stage3_dataset(
        events_df,
        window_sec=max(10, int(args.stage3_window_sec)),
        window_label_policy=args.stage3_window_label_policy,
        suspicious_min_ratio=max(0.0, min(1.0, args.suspicious_threshold)),
        malicious_min_ratio=max(0.0, min(1.0, args.malicious_threshold)),
    )
    stage3_before_rebalance = _stage3_split_positive_ratios(stage3_df)
    target_ratios = {
        'train': max(0.01, min(0.99, args.target_positive_train)),
        'val': max(0.01, min(0.99, args.target_positive_val)),
        'test': max(0.01, min(0.99, args.target_positive_test)),
    }
    stage3_df, rebalance_summary = rebalance_stage3_by_process(
        stage3_df,
        target_positive_ratios=target_ratios,
        max_change_ratio=max(0.05, min(0.95, args.stage3_rebalance_max_change)),
        tolerance=0.02,
        seed=args.seed,
    )
    stage3_after_rebalance = _stage3_split_positive_ratios(stage3_df)
    stage4_df = build_stage4_sequences(
        stage3_df,
        sequence_length=max(2, seq_len),
        stride=max(1, int(args.stage4_stride)),
    )

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_events_path = out_dir / 'raw_events.parquet'
    stage3_path = out_dir / 'stage3_dataset.parquet'
    stage4_path = out_dir / 'stage4_sequences.parquet'
    config_path = out_dir / 'dataset_config.json'

    if write_events:
        events_df.to_parquet(raw_events_path, index=False)
    if write_stage3:
        stage3_df.to_parquet(stage3_path, index=False)
    if write_stage4:
        stage4_df.to_parquet(stage4_path, index=False)

    quality = compute_data_quality(events_df, stage3_df, stage4_df)
    config = {
        'schema_version': SCHEMA_VERSION,
        'feature_list_hash': FEATURE_LIST_HASH,
        'seed': int(args.seed),
        'reproducibility_contract': 'Seed controls simulation, event generation, split assignment, and derived datasets deterministically.',
        'split_policy': args.split_policy,
        'label_policy': {
            'process_level': 'process_label derived from snapshot behavior and binary simulation label',
            'window_level': 'window labels aggregated by selected policy (max or ratio) from event labels',
            'sequence_level': 'stage4 sequence label equals last effective timestep label',
            'malicious_onset': '60% of process timeline for malicious, 75% for suspicious, never for benign',
        },
        'window_labeling': 'ratio_based' if args.stage3_window_label_policy == 'ratio' else 'max_based',
        'malicious_threshold': float(args.malicious_threshold),
        'suspicious_threshold': float(args.suspicious_threshold),
        'target_positive_ratios': {
            'train': float(target_ratios['train']),
            'val': float(target_ratios['val']),
            'test': float(target_ratios['test']),
        },
        'stage3_labeling': {
            'window_policy': args.stage3_window_label_policy,
            'suspicious_min_ratio': float(args.suspicious_threshold),
            'malicious_min_ratio': float(args.malicious_threshold),
            'target_positive_ratios': {
                'train': float(target_ratios['train']),
                'val': float(target_ratios['val']),
                'test': float(target_ratios['test']),
            },
            'rebalance_max_change_ratio': float(args.stage3_rebalance_max_change),
            'split_positive_ratio_before': stage3_before_rebalance,
            'split_positive_ratio_after': stage3_after_rebalance,
            'rebalance_summary': rebalance_summary,
        },
        'stage4_sequence_schema': {
            'fixed_length': int(max(2, seq_len)),
            'stride': int(max(1, args.stage4_stride)),
            'padding': 'zero feature rows',
            'mask_field': 'sequence_mask',
        },
        'calibration': {
            'class_profile': args.class_profile,
            'benign_ratio': float(args.benign_ratio),
            'overlap_ratio': float(args.overlap_ratio),
            'evasion_ratio': float(args.evasion_ratio),
            'hard_negative_ratio': float(args.hard_negative_ratio),
            'missing_rate': float(args.missing_rate),
            'outlier_rate': float(args.outlier_rate),
            'delay_rate': float(args.delay_rate),
            'duplicate_rate': float(args.duplicate_rate),
            'out_of_order_rate': float(args.out_of_order_rate),
        },
        'file_contracts': build_file_contracts(),
        'quality_checks': quality,
        'outputs': {
            'raw_events': str(raw_events_path) if write_events else None,
            'stage3_dataset': str(stage3_path) if write_stage3 else None,
            'stage4_sequences': str(stage4_path) if write_stage4 else None,
            'legacy_flat_dataset': str(out_path),
        },
    }
    config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
    
    benign = int((df['label'] == 0).sum())
    mal = int((df['label'] == 1).sum())
    print(f"Wrote {len(df):,} rows to {out_path}")
    print(f"Class balance: benign={benign:,} malicious={mal:,} ({mal/len(df):.2%} malicious)")
    print(f"Schema version: {SCHEMA_VERSION}")
    
    if args.enable_adversarial:
        adv_count = (df['_adversarial_technique'] != '').sum()
        print(f"Adversarial samples: {adv_count:,} ({adv_count/len(df):.2%})")
    
    if args.enable_attack_chain:
        avg_stages = df[df['label'] == 1]['_attack_stage_count'].mean()
        print(f"Average attack stages: {avg_stages:.1f}")
    
    if md_labels:
        print(f"Multi-dimensional labels: {len(md_labels)}")
    if write_events:
        print(f"Raw events: {raw_events_path}")
    if write_stage3:
        print(f"Stage3 dataset: {stage3_path}")
    if write_stage4:
        print(f"Stage4 sequences: {stage4_path}")
    print("Stage3 positive ratio by split (before -> after):")
    for split_name in ['train', 'val', 'test']:
        before = stage3_before_rebalance.get(split_name, {})
        after = stage3_after_rebalance.get(split_name, {})
        print(
            f"  {split_name}: "
            f"{before.get('positive_ratio', 0.0):.1%} ({before.get('rows', 0)} rows) -> "
            f"{after.get('positive_ratio', 0.0):.1%} ({after.get('rows', 0)} rows)"
        )
    print(f"Unified config: {config_path}")


if __name__ == '__main__':
    main()
