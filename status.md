# RDNXSYS Ransomware Detector - Architecture Status & Implementation Roadmap

**Last Updated:** April 13, 2026  
**Project Stage:** Multi-stage detector with Stages 1-4 implemented, Stage 5 and schema centralization pending

---

## Executive Summary

RDNXSYS is a multi-stage ransomware detection and response system designed for speed, effectiveness, and reversibility. 

**Current State:**
- ✅ Stages 1-4 fully implemented with production-ready code
- ✅ Two separate ML models (Stage 3: LightGBM, Stage 4: TabNet/Ensemble)
- ✅ Real-time feature extraction (87 features) with lifecycle aggregation
- ✅ Dashboard for monitoring and manual promotion
- ❌ Stage 5 (active mitigation engine) only has callback placeholders
- ⚠️ Feature schema and dataset generation scattered across multiple files (needs centralization)

**What We're Building:**
1. **Stage 5 Mitigation Engine** — Process kill/suspend, network isolation, file quarantine, with rollback capability
2. **Centralized Feature Schema** — Single source of truth for features across training and inference
3. **Unified Training Pipeline** — Consolidated dataset generation and model training scripts
4. **Configuration Management** — Centralized policy controls for Stage 5 behavior

---

## Architecture Overview by Stage

### Stage 1: Log Collection ✅ Complete
**Purpose:** Collect telemetry from system and applications  
**Components:**
- Sysmon Event Log listener (zero-loss bookmarking)
- NXLog TCP listener (async multi-client, port 5050)
- Honeypot file deployment and access detection

**Key Files:**
- `src/stage1_collection/sysmon_listener_pro.py` — Direct Sysmon reader
- `src/stage1_collection/honeypot_manager.py` — Safe file deployment
- `src/unified_launcher.py#L330+` — NXLog TCP async handler

**Throughput:** ~1000s events/sec, rate-limited per stage

---

### Stage 2: Prefilter ✅ Complete
**Purpose:** Reduce obvious benign traffic and attach heuristic scores

**11 Heuristics:**
1. File entropy > 7.9
2. Write burst ≥ 10/sec
3. Extension diversity ≥ 8 types
4. Mass file operations
5. Ransom note patterns (.crypt, .locked, README)
6. Shadow copy operations (vssadmin, wmic)
7. Registry persistence attempts
8. Network C2 domains (tor, onion, bitcoin TLDs)
9. File deletion burst ≥ 10
10. Honeypot access (instant 100x escalation)
11. Process behavior anomalies

**Configuration:** `src/stage2_prefilter/prefilter_engine.py` (hardcoded, ~60 defaults)

**Promotion Logic:** 
- Score ≥ 10.0 → forward to Stage 3 (all events promoted)
- All scoring attached as `__score`, `__reasons`

**Key Files:**
- `src/stage2_prefilter/prefilter_engine.py`
- `src/stage2_prefilter/correlation_engine.py`

---

### Stage 3: Fast ML Scorer ✅ Complete
**Purpose:** Real-time ML-based ransomware detection with tiered confidence

**Model:** LightGBM binary classifier (precomputed  0-100 score)

**Features:** 87 features including:
- CPU/RAM trends (5-min window, 300 samples)
- File I/O lifecycle (creates, deletes, entropy velocity)
- Process genealogy (spawn depth, injection flags)
- Network anomalies (burst detection, beacon intervals)
- Cryptographic API usage
- Memory/executable anomalies
- YARA rule matches (context-aware weighting)

**Tier System:**
- **LOW (0-59):** Benign → dropped
- **MEDIUM (60-79):** Suspicious → forward to Stage 4
- **HIGH (80-94):** Strong ransomware signal → immediate response + skip Stage 4
- **CRITICAL (95-100):** Near-certain ransomware → immediate response + Stage 4 forensics

**Immediate Response Actions (for HIGH/CRITICAL):**
- Currently: TODO placeholder in `src/unified_launcher.py#L308`
- Will be: Forward to Stage 5 with tier and score

**Key Files:**
- `src/stage3_feature_extraction/stage3_engine.py` — Orchestrator
- `src/stage3_feature_extraction/feature_extractor.py` — 87-feature extraction
- `src/stage3_feature_extraction/ml_scorer2.py` — LightGBM inference
- `src/stage3_feature_extraction/yara_scanner.py` — YARA integration
- Models: `models/stage3_balanced_v2` (LightGBM .txt format)

**Latency:** ~10-50ms per event (must be inline with ingestion)

---

### Stage 4: Full Scorer (Deep Analysis) ✅ Complete
**Purpose:** Context-rich confirmation and override with explainability

**Models:** TabNet primary, optional Ensemble (XGBoost fallback)

**Context Layers:**
- Graph analysis (process tree depth, network degree anomalies)
- Temporal model (5min/30min spike detection, baseline deviation)
- ML classifier (TabNet confident scoring)
- Rule engine (heuristic overrides)

**Multi-Factor Weights:**
- ML Score: 40%
- Graph Score: 25%
- Temporal Score: 25%
- Rule Score: 10%

**Decision Verdicts:**
- **MALICIOUS** (confidence ≥ 0.7) → Stage 5 action + forensics
- **SUSPICIOUS** (0.4 ≤ conf < 0.7) → Stage 5 action + review
- **BENIGN** (confidence < 0.4) → drop
- **UNKNOWN** (insufficient data) → quarantine for review

**Key Files:**
- `src/stage4_full_scorer/stage4_engine.py` — Orchestrator
- `src/stage4_full_scorer/decision_engine.py` — Final verdict logic
- `src/stage4_full_scorer/graph_analyzer.py` — Genealogy + network context
- `src/stage4_full_scorer/temporal_model.py` — Time-series anomalies
- `src/stage4_full_scorer/ml_classifier.py` — TabNet/Ensemble inference
- Models: Optional `models/stage4_tabnet_model` + `models/stage4_ensemble`

**Latency:** ~200-500ms allowable (parallel to Stage 3, not on critical path)

---

### Stage 5: Active Mitigation & Response ❌ NOT IMPLEMENTED

**Purpose:** Execute immediate containment and reversible remediation

**Current Status:**
- Only callback placeholders exist
- `src/unified_launcher.py#L189` — `stage5_callback` attribute (unused)
- `src/unified_launcher.py#L294-320` — `_on_stage3_immediate_response()` (TODO comment at line 308)

**What Will Be Implemented:**

#### HIGH Tier (80-94) Action Policy:
1. **Process Suspension** — Suspend all threads (not kill, allow resume)
2. **Network Containment** — Block outbound TCP/UDP (Windows Firewall rules)
3. **Metadata Capture** — Record PID, image path, command line, network sockets
4. **Pre-Action Snapshot** — Store state for potential rollback

#### CRITICAL Tier (95-100) Action Policy:
1. **Process Termination** — Kill process tree (parent + all children)
2. **Network Isolation** — Same as HIGH
3. **Quarantine Preparation** — Mark binary for move to isolation directory
4. **Memory Dump** — Capture minidump for forensics
5. **Full Forensics** — Always forward to Stage 4 for analysis

#### Override & Rollback Capability:
- **Stage 4 Downgrade:** If Stage 4 later determines the event is benign, triggered rollback:
  - **Guaranteed Rollback:** Remove firewall rules, restore quarantined files
  - **Best-Effort Rollback:** Attempt process restart using recorded metadata
  - **Analyst Notification:** Log all rollback attempts with confidence scores

**New Files to Create:**
- `src/stage5_mitigation/stage5_engine.py` — Policy orchestrator
- `src/stage5_mitigation/process_containment.py` — PID validation, suspend/kill/terminate
- `src/stage5_mitigation/network_isolation.py` — Firewall rule injection/removal
- `src/stage5_mitigation/file_quarantine.py` — Safe file move with copy-verify-move pattern
- `src/stage5_mitigation/rollback_engine.py` — Undo capability with capability matrix
- `src/stage5_mitigation/forensics_capture.py` — Memory dumps, state snapshots

---

## Current Implementation State - Detailed

### What's Working ✅

| Component | Status | Notes |
|-----------|--------|-------|
| Stage 1 (Sysmon collection) | ✅ Complete | Zero-loss, rate-limited |
| Stage 1 (NXLog TCP listener) | ✅ Complete | Async, multi-client |
| Stage 2 (Prefilter) | ✅ Complete | 11 heuristics, ~10.0 threshold |
| Stage 3 (Feature extraction) | ✅ Complete | 87 features, real-time |
| Stage 3 (ML scoring) | ✅ Complete | LightGBM loaded, 0-100 scale |
| Stage 3 (YARA scanning) | ✅ Complete | ~400 rules, context-aware |
| Stage 3 (Tier mapping) | ✅ Complete | LOW/MEDIUM/HIGH/CRITICAL |
| Stage 4 (Graph analysis) | ✅ Complete | Process tree + network |
| Stage 4 (Temporal model) | ✅ Complete | Spike detection, baselines |
| Stage 4 (ML classifier) | ✅ Complete | TabNet optional, ensemble ready |
| Stage 4 (Rule engine) | ✅ Complete | Heuristic overrides |
| Stage 4 (Decision engine) | ✅ Complete | Multi-factor verdicts |
| Dashboard | ✅ Complete | Real-time WebSocket updates |
| Dataset Recording | ✅ Complete | Parquet export, annotation support |

### What's Missing ❌

| Component | Impact | Priority |
|-----------|--------|----------|
| **Stage 5 Engine** | Cannot contain detected ransomware | 🔴 CRITICAL |
| **Process Kill/Suspend** | No actual response to threats | 🔴 CRITICAL |
| **Network Isolation** | C2 communication continues | 🔴 CRITICAL |
| **File Quarantine** | Malicious files remain accessible | 🔴 CRITICAL |
| **Rollback Capability** | False positives permanently damage system | 🔴 CRITICAL |
| **Centralized Schema** | Feature consistency risk, training/inference skew | 🟠 HIGH |
| **Unified Training Pipeline** | Dataset generation scattered, hard to maintain | 🟠 HIGH |
| **Stage 5 Config** | Enforcement policies not tunable | 🟠 HIGH |
| **Audit Trail** | No persistent action history | 🟠 HIGH |

---

## What We Will Implement - Roadmap

### Phase 1: Stage 5 Policy Foundation & Core Actions

**Goal:** Implement tiered mitigation actions with safety validation

**Steps:**
1. Create `src/stage5_mitigation/stage5_engine.py` with policy router
   - Route Stage 3 immediate responses and Stage 4 verdicts
   - Encode action state machine: CONTAIN → ESCALATE/ROLLBACK/MONITOR
   - Validate tier + confidence combinations

2. Create `src/stage5_mitigation/process_containment.py`
   - Windows API integration (TerminateProcess, SuspendProcess)
   - PID + image path + command-line triple validation
   - Atomic family kill (parent first, then children)
   - Pre-action metadata capture (for rollback)
   - Safety checks: prevent killing system processes (svchost, lsass, csrss)

3. Create `src/stage5_mitigation/network_isolation.py`
   - Windows Firewall rule injection (netsh.exe API or WMI)
   - Deterministic rule naming: `RDNXSYS_BLOCK_<IP>_<TIMESTAMP>`
   - Track all rules in memory (for cleanup during rollback)
   - Outbound-only blocking (don't interfere with return packets)

4. Extend `src/config/edr_config.py`
   - Add `Stage5Config` dataclass with toggles:
     - `enforcement_mode` (dry_run vs active)
     - `high_tier_action` (suspend vs kill vs monitor)
     - `enable_network_isolation` (bool)
     - `enable_quarantine` (bool)
     - `rollback_mode` (full vs minimal vs none)
     - `allow_process_restart` (bool)

5. Update `src/unified_launcher.py`
   - Replace placeholder `_on_stage3_immediate_response()` with real Stage 5 call
   - Import `Stage5Engine` and initialize on launcher startup
   - Route both Stage 3 and Stage 4 events to Stage 5

**Deliverables:**
- Stage 5 engine that can suspend/kill processes safely
- Network isolation with firewall rules
- Configuration layer for policies
- Safety validation to prevent wrong-target actions

**Estimated Effort:** 5-6 person-days

---

### Phase 2: File Quarantine & Forensics

**Goal:** Capture evidence and isolate malicious binaries

**Steps:**
1. Create `src/stage5_mitigation/file_quarantine.py`
   - Safe move pattern: copy → hash verification → delete original
   - Quarantine directory: `C:\Quarantine\{timestamp}_{original_basename}`
   - Metadata journal with original path + hash + detection context
   - Handle in-use files (open handles prevent deletion)

2. Create `src/stage5_mitigation/forensics_capture.py`
   - Memory minidump capture using WinDbg automation
   - VSS snapshot request pre-action (defensive backup)
   - Registry snapshot before/after action
   - Correlation ID linking all artifacts

3. Update `stage3_engine.py` / `stage4_engine.py` events
   - Add `__stage5_action_id` field for tracing
   - Add `__quarantine_path` field after move
   - Add `__forensics_bundle` field with dump/snapshot references

**Deliverables:**
- Safe file quarantine with verification
- Forensic evidence capture
- Tracing fields in event pipeline

**Estimated Effort:** 4-5 person-days

---

### Phase 3: Rollback Engine & Stage 4 Arbitration

**Goal:** Allow Stage 4 to downgrade or undo Stage 5 actions

**Steps:**
1. Create `src/stage5_mitigation/rollback_engine.py`
   - Track all Stage 5 actions with timestamps and correlation IDs
   - **Guaranteed Rollback Capabilities:**
     - Remove Windows Firewall rules by deterministic name
     - Restore quarantined files from metadata (copy back + hash verify)
   - **Best-Effort Rollback Capabilities:**
     - Process restart using recorded image path + command line
     - Whitelist check: only restart if in trusted paths (e.g., System32, Program Files)
     - Fallback: if restart unsafe, log analyst alert + exit
   - Idempotent: calling rollback twice is safe

2. Implement Stage 3/Stage 4 arbitration logic in `unified_launcher.py`
   - Stage 3 can trigger fast containment (HIGH/CRITICAL)
   - Stage 4 can confirm, escalate, or downgrade
   - Downgrade invokes automatic rollback
   - Escalate triggers additional firewall rules and quarantine

3. Store action history in database
   - Use `src/dashboard/dashboard.db` (SQLite)
   - Table: `stage5_actions` (action_id, pid, image, action, status, timestamp, rollback_timestamp, correlation_id)
   - Query interface for dashboard timeline

**Deliverables:**
- Rollback engine with guaranteed + best-effort capabilities
- Arbitration logic between stages
- Persistent action audit trail

**Estimated Effort:** 5-6 person-days

---

### Phase 4: Centralized Feature Schema & Training Pipeline

**Goal:** Single source of truth for features, datasets, and models

**Steps:**
1. Create `src/ml/schema.py`
   - Define `EXPECTED_FEATURES` (87 items)
   - Define `STAGE3_FEATURES = EXPECTED_FEATURES`
   - Define `STAGE4_EXTENDED_FEATURES = EXPECTED_FEATURES + [graph, temporal, context]`
   - Include schema version and hash (for validation)
   - Export as module for all imports

2. Create `src/ml/dataset_loader.py`
   - Unified loader that validates schema on load
   - Check feature hash matches expected
   - Detect and warn on missing/extra features
   - Auto-fill missing features with 0.0

3. Consolidate dataset generation
   - Keep canonical: `dataset_generator_v3_complete.py` (in root)
   - Deprecate: `Modifications/dataset_generator_v3_complete.py` (duplicate)
   - Update imports: remove hardcoded EXPECTED_FEATURES, import from `src/ml/schema.py`

4. Consolidate training scripts
   - Keep: `train_ml_model_v11.py` → rename to `train_stage3.py` (explicit)
   - Move: `Modifications/train_ml_model_v12_stage3_enhanced.py` → `train_stage3_enhanced.py` (with improvements)
   - Create: `train_stage4.py` (new, explicit Stage 4 training)
   - All training scripts import from `src/ml/schema.py`

5. Update all feature extraction code
   - `feature_extractor.py` — import `EXPECTED_FEATURES` from schema
   - `ml_scorer2.py` — import `EXPECTED_FEATURES` from schema
   - `ml_classifier.py` — import `STAGE4_EXTENDED_FEATURES` from schema
   - `unified_launcher.py` — pass schema features to dataset recorder

**Deliverables:**
- Single `src/ml/schema.py` as golden feature definition
- All training and inference code imports from schema
- Eliminated duplicate feature lists
- Safer train/inference consistency

**Estimated Effort:** 2-3 person-days

---

### Phase 5: Integration & End-to-End Wiring

**Goal:** Wire all pieces together and validate full pipeline

**Steps:**
1. Integration tests
   - Synthetic HIGH event → suspend + isolate + metadata capture
   - Synthetic CRITICAL event → kill + quarantine + forensics + Stage 4 forward
   - Stage 4 benign downgrade → automatic rollback + process restart attempt

2. Failure hardening
   - Any Stage 5 sub-action failure must not crash pipeline
   - Catch exceptions, log, degrade to safe fallback
   - Example: if firewall rule injection fails, still suspend process + log alert

3. Load testing
   - Measure Stage 5 latency on event stream
   - Ensure Stage 1/2 ingestion not blocked by Stage 5 actions
   - Target: Stage 5 adds <100ms per HIGH/CRITICAL, no backpressure

4. Manual validation on Windows lab VM
   - Deploy RDNXSYS end-to-end
   - Trigger test ransomware-like binaries (safe, sandboxed)
   - Verify suspend/kill works
   - Trigger firewall rule injection
   - Test rollback on analyst downgrade

**Deliverables:**
- Full end-to-end system tests passing
- Failure recovery validated
- Performance targets met
- Lab VM manual validation complete

**Estimated Effort:** 3-4 person-days

---

## File Organization - Current vs. Future

### Current Structure (Scattered)
