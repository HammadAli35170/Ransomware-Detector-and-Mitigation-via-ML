# Stage 4 Feature Schema

## Purpose
Stage 4 is a second-pass ML model that performs **fusion classification** across multiple data dimensions:
- **Graph Structure**: Process hierarchy, spawning patterns, sibling relationships
- **Temporal Dynamics**: Event rates, duration to first alert, lifecycle analysis
- **Stage 3 Outputs**: ML scores, YARA confidence, behavioral signals
- **Risk Stratification**: Combines deep learning with behavioral anomalies for high-precision classification

## Input Dataset Format

Each Stage 4 training sample aggregates Stage 3 events for a single **PID**, producing one row per process session.

### Key Identifiers
| Field | Type | Description |
|-------|------|-------------|
| `sample_id` | str | Unique identifier (uuid) |
| `pid` | int | Process ID |
| `image` | str | Executable path |
| `host` | str | Hostname |
| `start_epoch` | float | Process start timestamp |
| `end_epoch` | float | Last activity timestamp (or current) |
| `label` | int | 0=benign, 1=malicious, -1=unknown |

### Stage 3 Input Features (80+ base features)
These are carried forward directly from Stage 3 feature extraction:
- File I/O: `files_created`, `files_deleted`, `file_entropy_mean`, `file_entropy_variance`
- Network: `network_burst_60s`, `destination_ips_count`, `dns_lookups_count`
- Process: `thread_count_peak`, `handle_count_peak`, `spawn_count`
- Memory: `memory_size_peak`, `memory_entropy_mean`
- API Calls: `crypt_api_calls`, `virtualalloc_calls`, `writeprocessmemory_calls`, `createremotethread_calls`
- Privileges: `privilege_escalations`, `token_manipulations`
- Registry: `registry_modifications_count`, `suspicious_registry_keys_count`

### Stage 3 Aggregated Outputs (Fusion Features)
| Field | Type | Description |
|-------|------|-------------|
| `stage3_score_max` | float | Maximum Stage 3 score across all events |
| `stage3_score_mean` | float | Mean Stage 3 score |
| `stage3_score_std` | float | Standard deviation of Stage 3 score |
| `stage3_tier_distribution` | dict | {tier: count} for low/medium/high/critical |
| `yara_weighted_confidence_max` | float | Highest YARA confidence |
| `yara_match_types` | dict | {rule_name: count} e.g., {"cobalt_strike": 5, "ransomware": 3} |
| `behavioral_signal_count_total` | int | Sum of all behavioral signals |
| `events_promoted_from_stage3` | int | Number of events that reached Stage 3 |

### Graph Structure Features (Process Hierarchy)
| Field | Type | Description |
|-------|------|-------------|
| `parent_pid` | int | Direct parent PID |
| `parent_image` | str | Parent executable path |
| `is_parent_suspicious` | bool | Whether parent has high Stage 3 score |
| `parent_chain_depth` | int | Distance to root process (e.g., 3 for explorer→cmd→powershell→injected) |
| `parent_chain_suspicious_count` | int | Number of suspicious processes in parent chain |
| `sibling_pids` | list[int] | Other processes spawned by same parent |
| `sibling_count` | int | Number of siblings |
| `sibling_max_score` | float | Highest Stage 3 score among siblings |
| `child_pids` | list[int] | Process tree children |
| `child_count` | int | Number of children |
| `child_max_score` | float | Highest Stage 3 score among children |
| `tree_depth` | int | Distance from root (0 for system processes) |
| `subtree_score_sum` | float | Sum of Stage 3 scores in subtree |
| `subtree_suspicious_count` | int | Count of suspicious processes in subtree |

### Temporal Dynamics Features
| Field | Type | Description |
|-------|------|-------------|
| `process_age_sec` | float | Seconds from start to end of activity |
| `event_rate_per_sec` | float | Total events / process_age_sec |
| `first_stage3_alert_sec` | float | Seconds from start to first Stage 3 score > 14 |
| `alert_onset_ratio` | float | first_stage3_alert_sec / process_age_sec (0=instant, 1=never occurs) |
| `stage3_promotion_rate` | float | events_promoted_from_stage3 / total_events_in_window |
| `suspicious_event_cluster_count` | int | Number of separate time windows with 3+ suspicious events |
| `max_event_rate_60s` | float | Highest event rate in any 60-second window |
| `behavioral_signal_persistence` | float | Fraction of events with behavioral signals |

### Trust & Signature Features
| Field | Type | Description |
|-------|------|-------------|
| `is_signed` | bool | Executable is digitally signed |
| `is_microsoft_signed` | bool | Signed by Microsoft |
| `cert_mismatch` | bool | Signing cert present but mismatches on runtime |
| `path_anomaly` | bool | Executable in suspicious location |
| `pe_header_mismatch` | bool | PE header tampering detected |

### Risk Stratification Features
| Field | Type | Description |
|-------|------|-------------|
| `behavioral_signal_entropy` | float | Entropy of signal type distribution |
| `stage3_elevation_anomaly` | float | Ratio of high-tier events to total |
| `process_injection_confidence` | float | Composite score for injection likelihood |
| `evasion_technique_count` | int | Number of distinct evasion techniques observed |
| `lateral_movement_indicators` | int | Network anomalies suggesting lateral movement |
| `data_exfil_indicators` | int | Compression/archive/upload combinations |
| `persistence_indicators` | int | Registry/scheduled_task/startup modifications |
| `privilege_escalation_indicators` | int | Token manipulation / UAC bypass indicators |

## Output Format
### Prediction Output
| Field | Type | Values |
|-------|------|--------|
| `verdict` | str | "benign", "suspicious", "malicious", "unknown" |
| `confidence` | float | 0.0 to 1.0 |
| `stage4_score` | float | 0 to 100 (computed from model probability + auxiliary signals) |
| `ml_probability` | float | Raw model output (0.0 to 1.0, likelihood of malicious class) |

## Model Type
- **Algorithm**: LightGBM (binary classification, same as Stage 3)
- **Classes**: Binary (benign=0, malicious=1)
- **Target Objective**: Binary cross-entropy
- **Target Metrics**: 
  - Stage 3: optimize recall (catch true positives, esp. ransomware)
  - Stage 4: optimize precision (reduce false positives from Stage 3 overflow)
- **Calibration**: Logistic regression on model probabilities to ensure 0.5 = 50% true positive rate

## Training Data Requirements
- **Minimum samples**: 500 benign + 500 malicious = 1000 minimum
- **Label sources**: 
  - Manual labeling (dashboard UI or batch label file)
  - Synthetic labels (benign = low Stage 3 scores + no alerts, malicious = high Stage 3 scores + YARA matches)
- **Train/Val/Test split**: 60% / 20% / 20%
- **Class weight**: Adjust for imbalance; typical ratio is 70% benign / 30% malicious in real EDR environments

## Feature Engineering Notes
- **Graph features** capture coordinated attacks (e.g., parent spawns malicious children)
- **Temporal features** distinguish slow-moving persistence from burst exfiltration
- **Aggregation windows** use all Stage 3 events for a PID across its entire lifetime (not time-windowed)
- **Missing values**: Filled with 0 or "unknown" (safe defaults)
- **Feature scaling**: LightGBM handles this internally, but normalization can improve training speed

