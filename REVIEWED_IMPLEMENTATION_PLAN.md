# RDNXSYS - Reviewed Implementation Plan with Improvements

**Last Updated:** April 13, 2026  
**Status:** ✅ ARCHITECTURE FINALIZED & REVIEWED  
**Ready to Implement:** YES (after improvement fixes)

---

## Executive Summary

RDNXSYS is a **5-stage ransomware detection and response system**. Stages 1-4 are production-ready with code review completed. Stage 5 (mitigation) + schema centralization pending.

**Architecture Assessment:** ✅ SOUND
- Two-model approach correct (Stage 3 fast + Stage 4 deep)
- Tiered confidence system excellent
- Cascading analysis flow optimal
- Feature engineering comprehensive (87 features)

**Improvements Needed:** 🔴 6 CRITICAL + 🟡 11 HIGH (before & during implementation)

---

## Part I: Current Implementation Status

### Stage 1: Log Collection ✅ COMPLETE & PRODUCTION-READY

**Purpose:** Real-time event collection from Windows infrastructure

**Components Implemented:**
- ✅ Sysmon Event Log reader (zero-loss with bookmarking)
- ✅ NXLog TCP async listener (multi-client, port 5050)
- ✅ Honeypot file deployment + access detection
- ✅ Rate limiting per stage

**Key Files:**
- `src/stage1_collection/sysmon_listener_pro.py` — Sysmon reader
- `src/stage1_collection/honeypot_manager.py` — Honeypot manager
- `src/unified_launcher.py#L330+` — NXLog TCP listener

**Throughput:** 1000s events/sec  
**Quality:** ✅ Ready

---

### Stage 2: Prefilter ✅ COMPLETE & PRODUCTION-READY

**Purpose:** Reduce obvious benign traffic, attach heuristic scores

**11 Heuristics Implemented:**
1. ✅ File entropy > 7.9
2. ✅ Write burst ≥ 10/sec
3. ✅ Extension diversity ≥ 8 types
4. ✅ Mass file operations (docs/xls/pdf)
5. ✅ Ransom note patterns (.crypt, .locked, README)
6. ✅ Shadow copy operations (vssadmin, wmic)
7. ✅ Registry persistence (RunOnce, Winlogon)
8. ✅ Network C2 domains (tor, onion, bitcoin)
9. ✅ File deletion bursts ≥ 10
10. ✅ Honeypot access (instant escalation)
11. ✅ Process behavior anomalies

**Configuration:**
```
Score promotion threshold: 10.0 (all events ≥ 10 forward to Stage 3)
Processing: ThreadPool with ProcessTracker
Scoring: Heuristic + temporal windowing (30sec)
```

**Key Files:**
- `src/stage2_prefilter/prefilter_engine.py` — Main logic
- `src/stage2_prefilter/correlation_engine.py` — Event correlation

**Quality:** ✅ Ready

---

### Stage 3: Fast ML Scorer ✅ COMPLETE & TESTED

**Purpose:** Real-time ML-based ransomware detection with tiered confidence

**Model Architecture:**
- **Primary:** LightGBM binary classifier (0-100 scoring)
- **Auxiliary:** Fallback static scorer (if model unavailable)
- **Feature Count:** 87 comprehensive features
- **Latency:** 10-50ms per event (inline requirement)

**Features Implemented:**
- ✅ CPU/RAM trends (5-min window, 300 samples)
- ✅ File I/O lifecycle (creates, deletes, deletions, entropy)
- ✅ Process genealogy (spawn depth, injection flags)
- ✅ Network anomalies (burst detection, beacon intervals)
- ✅ Cryptographic API usage (threshold crossing)
- ✅ Memory/executable manipulation detection
- ✅ YARA rule integration (~400 curated rules, context-aware)

**Tier System Currently Implemented:**
```
LOW (0-59):       Benign → Dropped silently
MEDIUM (60-79):   Suspicious → Forward to Stage 4 (no immediate action)
HIGH (80-94):     Strong signal → Immediate response callback ⚠️ (NEEDS SPLIT)
CRITICAL (95-100): Near-certain → Immediate response + Stage 4
```

**Key Files:**
- `src/stage3_feature_extraction/stage3_engine.py` — Orchestrator
- `src/stage3_feature_extraction/feature_extractor.py` — 87 features
- `src/stage3_feature_extraction/ml_scorer2.py` — LightGBM inference
- `src/stage3_feature_extraction/yara_scanner.py` — YARA integration

**Model Location:** `models/stage3_balanced_v2` (LightGBM text format)

**Quality:** ✅ Ready (with improvements applied)

---

### Stage 4: Full Scorer (Deep Analysis) ✅ COMPLETE & TESTED

**Purpose:** Context-rich confirmation and override with multi-factor analysis

**Analysis Components Implemented:**
- ✅ **Graph Analyzer:** Process tree depth, network degree, file access patterns
- ✅ **Temporal Model:** 5min + 30min spike detection, baseline deviation scoring
- ✅ **ML Classifier:** TabNet primary, optional XGBoost ensemble
- ✅ **Rule Engine:** Heuristic overrides (non-YARA rules)
- ✅ **Decision Engine:** Multi-factor weighted combination

**Multi-Factor Weighting:**
```
ML Score:        40% (TabNet classification confidence)
Graph Score:     25% (relationship anomalies, centrality)
Temporal Score:  25% (time-series spikes, baselines)
Rule Score:      10% (heuristic overrides)
```

**Decision Verdicts Implemented:**
```
MALICIOUS (confidence ≥ 0.7):   → Stage 5 action + forensics
SUSPICIOUS (0.4 ≤ conf < 0.7):  → Stage 5 action + review
BENIGN (confidence < 0.4):       → Dropped
UNKNOWN (insufficient data):     → Quarantine for analyst review  
```

**Key Files:**
- `src/stage4_full_scorer/stage4_engine.py` — Orchestrator
- `src/stage4_full_scorer/decision_engine.py` — Final verdict logic
- `src/stage4_full_scorer/graph_analyzer.py` — Process relationships
- `src/stage4_full_scorer/temporal_model.py` — Time-series analysis
- `src/stage4_full_scorer/ml_classifier.py` — TabNet/Ensemble inference
- `src/stage4_full_scorer/rule_engine.py` — Rule evaluation

**Model Paths:** `models/stage4_tabnet_model`, `models/stage4_ensemble_model` (optional)

**Quality:** ✅ Ready (with improvements applied)

---

### Stage 5: Active Mitigation & Response ❌ PLACEHOLDER ONLY

**Purpose:** Execute immediate containment and reversible remediation

**Current Status:** 
- ❌ Only callback placeholders (TODO at line 308)
- ❌ No actual process kill/suspend
- ❌ No network isolation
- ❌ No file quarantine
- ❌ No rollback capability

**Callback Locations:**
- `src/unified_launcher.py#L189` — `stage5_callback` attribute
- `src/unified_launcher.py#L294-320` — `_on_stage3_immediate_response()` (TODO)

**To Be Implemented:**
- ✋ Process kill/suspend (Windows API)
- ✋ Network isolation (Windows Firewall)
- ✋ File quarantine (safe move pattern)
- ✋ Rollback engine (undo capability)
- ✋ Forensics capture (memory dumps, state snapshots)

**Quality:** ❌ Not ready (requires implementation)

---

### Configuration Management ⚠️ PARTIAL

**Current State:**
- ✅ `src/config/edr_config.py` — Defines Stage2/3/4 config classes
- ⚠️ Feature thresholds **hardcoded in code** (not configurable)
- ⚠️ No Stage5Config yet

**Thresholds Currently Hardcoded:**
```python
# Stage 3 (in ml_scorer2.py):
if score < 60: tier = 'low'          # HARDCODED
elif score < 80: tier = 'medium'     # HARDCODED
elif score < 95: tier = 'high'       # HARDCODED
else: tier = 'critical'              # HARDCODED

# Stage 4 (in decision_engine.py):
malicious_threshold = 70.0           # HARDCODED
suspicious_threshold = 50.0          # HARDCODED
unknown_threshold = 30.0             # HARDCODED
```

**Dashboard:** ✅ Real-time WebSocket updates

**Quality:** ⚠️ Config tuning required before Stage 5

---

## Part II: Critical Improvements Required

### 🔴 CRITICAL #1: Move Tier Boundaries to Config

**Current Issue:**
- Tier thresholds (60/79/94) hardcoded in `ml_scorer2.py`
- Cannot adjust without code change + model retrain
- No A/B testing capability for threshold tuning

**Impact if Not Fixed:**
- ❌ Cannot tune detection sensitivity
- ❌ False positive rate uncontrollable
- ❌ Testing blocked (can't try different thresholds)

**Solution:**
```python
# Add to edr_config.py Stage3Config:
@dataclass
class Stage3Config:
    tier_low_max: float = 59.0
    tier_medium_max: float = 79.0
    tier_high_max: float = 94.0
    tier_critical_min: float = 95.0
```

**Files to Modify:**
1. `src/config/edr_config.py` — Add tier thresholds to Stage3Config
2. `src/stage3_feature_extraction/ml_scorer2.py` — Load from config instead of hardcoded
3. `src/unified_launcher.py` — Pass config to Stage3Engine

**Effort:** 2 hours  
**Blocker for Stage 5:** YES

---

### 🔴 CRITICAL #2: Triple-Check PID Before Kill (Prevent Wrong Process Termination)

**Current Issue:**
- Stage 5 will kill process based on PID alone
- OS can reuse PIDs (1234 dies → new process gets 1234)
- No validation that PID is actually the malicious process

**Impact if Not Fixed:**
- ❌ Kill Process A (PID 1234, ransomware)
- ❌ OS reuses PID 1234 for Process B (svchost, benign)
- ❌ svchost killed → system becomes unstable
- ❌ Permanent damage (can't undo kill)

**Solution:**
```python
# Stage 5 must validate BEFORE kill:
def validate_process_identity(pid, expected_image, expected_cmdline):
    """Triple validation: PID + ImagePath + CommandLine"""
    
    # 1. Check if process exists with this PID
    try:
        p = psutil.Process(pid)
        current_image = p.exe()
        current_cmdline = ' '.join(p.cmdline())
    except psutil.NoSuchProcess:
        raise ValueError(f"PID {pid} no longer exists")
    
    # 2. Verify image path matches expected
    if expected_image.lower() not in current_image.lower():
        raise ValueError(f"Image mismatch: expected {expected_image}, got {current_image}")
    
    # 3. Verify command line matches expected pattern
    if expected_cmdline and expected_cmdline.lower() not in current_cmdline.lower():
        raise ValueError(f"CommandLine mismatch: expected pattern {expected_cmdline}")
    
    return True  # Safe to proceed
```

**Files to Create:**
- `src/stage5_mitigation/process_validation.py` — PID validation logic

**Effort:** 3 hours  
**Blocker for Stage 5:** YES (CRITICAL)

---

### 🔴 CRITICAL #3: YARA Context Should NOT Boost Score

**Current Issue:**
```python
# Stage 3 currently does:
if yara_matched:
    score += yara_weighted_confidence  # Could boost 60 → 80 (WRONG!)
```

**Problem:**
- YARA matches have high false-positive rate (signatures can be evaded)
- Behavioral signals (entropy, file ops, CPU) are more reliable
- YARA match boosting score might trigger HIGH tier on benign process
- Stage 5 immediate response activated on weak signal

**Impact if Not Fixed:**
- ❌ False positive ransomware detection (YARA alone insufficient)
- ❌ Stage 5 suspends benign process
- ❌ System disruption from false positives

**Solution:**
```python
# AFTER FIX: YARA becomes context, not score boost
# Stage 3:
event['__yara_matched'] = True
event['__yara_rules'] = ['ransomware.conti', 'trojan.generic']
event['__yara_context'] = 'memory'  # or 'executable', 'script', 'document'
# NO score boost from YARA!

# Stage 4 integrates YARA with behavioral signals:
combined_score = (
    ml_score * 0.4 +           # ML (behavioral)
    graph_score * 0.25 +       # Process relationships
    temporal_score * 0.25 +    # Time-series anomalies
    rule_score * 0.1           # Rules (including YARA context)
)
```

**Files to Modify:**
1. `src/stage3_feature_extraction/yara_scanner.py` — Remove score boost
2. `src/stage3_feature_extraction/stage3_engine.py` — Pass YARA as event context only
3. `src/stage4_full_scorer/rule_engine.py` — Weight YARA with behavioral signals

**Effort:** 4 hours  
**Blocker for Stage 5:** YES

---

### 🔴 CRITICAL #4: Split HIGH Tier Into Confidence Bands

**Current Issue:**
```
HIGH (80-94): Same action regardless of confidence
- 80% ransomware → suspend + isolate
- 94% ransomware → suspend + isolate (identical action)
```

**Problem:**
- No ability to escalate if confidence increases
- No graduated response based on certainty
- High false-positive harm (suspend on 80% confidence)

**Solution:**
```python
class RiskTier(Enum):
    LOW = "low"              # 0-59:    Benign
    MEDIUM = "medium"        # 60-79:   Suspicious (Stage 4 only)
    HIGH_LOW = "high_low"    # 80-87:   Strong signal (suspend only)
    HIGH_HIGH = "high_high"  # 87-94:   Very strong (suspend + isolate)
    CRITICAL = "critical"    # 95-100:  Near-certain (suspend + isolate + quarantine)
```

**Stage 5 Actions by Tier:**
```
MEDIUM:     NO immediate action (Stage 4 only)
HIGH_LOW:   Suspend process only (reversible)
HIGH_HIGH:  Suspend + network isolate
CRITICAL:   Suspend + isolate + quarantine + memory dump
```

**Files to Modify:**
1. `src/stage3_feature_extraction/stage3_engine.py` — Update RiskTier enum
2. `src/stage3_feature_extraction/ml_scorer2.py` — Update tier mapping
3. `src/unified_launcher.py` — Update Stage 5 policy for new tiers

**Effort:** 5 hours  
**Blocker for Stage 5:** YES

---

### 🔴 CRITICAL #5: Add Verdict Persistence (Cache) to Stage 4

**Current Issue:**
- Same process analyzed multiple times → inconsistent verdicts
- No memory of prior decisions
- Replay attack: can get different verdicts for same process signature

**Problem:**
- Stage 5 might receive conflicting signals
- Analyst sees process marked benign, then malicious (confusing)
- No decision consistency

**Solution:**
```python
class Stage4Engine:
    def __init__(self):
        self.verdict_cache = {}   # PID → (decision, timestamp)
        self.verdict_cache_ttl = 300  # 5 minutes
        self.verdict_cache_lock = threading.RLock()
    
    def process_event(self, event):
        pid = event.get('ProcessID')
        now = time.time()
        
        # Check cache first
        with self.verdict_cache_lock:
            if pid in self.verdict_cache:
                cached_decision, cached_time = self.verdict_cache[pid]
                age = now - cached_time
                if age < self.verdict_cache_ttl:
                    logger.info(f"Returning cached verdict for PID {pid} (age={age:.1f}s)")
                    # Return cached decision, but update timestamp
                    self.verdict_cache[pid] = (cached_decision, now)
                    return cached_decision
        
        # Analyze if not cached (or cache expired)
        decision = self._analyze_process(event)
        
        # Store in cache
        with self.verdict_cache_lock:
            self.verdict_cache[pid] = (decision, now)
        
        return decision
```

**Files to Modify/Create:**
1. `src/stage4_full_scorer/stage4_engine.py` — Add verdict cache logic
2. Create `src/stage5_mitigation/verdict_store.py` — Persistent verdict storage (DB)

**Effort:** 3 hours  
**Blocker for Stage 5:** YES

---

### 🔴 CRITICAL #6: Stage 5 Actions Must Be Atomic (All-or-Nothing)

**Current Issue:**
- No transaction semantics for Stage 5 actions
- Might kill process but fail to capture memory (evidence lost)
- Network isolation succeeds but file quarantine fails (incomplete)

**Problem:**
- Forensic evidence can be lost
- Inconsistent system state (partially mitigated)
- Rollback difficult if some actions half-succeeded

**Solution:**
```python
# Stage 5 action sequence (ATOMIC):

class Stage5Engine:
    def execute_response(self, event, tier):
        """Execute response actions atomically"""
        
        action_id = str(uuid.uuid4())
        logger.info(f"Stage5 action {action_id} starting for tier {tier}")
        
        # Step 1: PREPARE (gather everything needed, no side effects yet)
        try:
            pid = event.get('ProcessID')
            image = event.get('Image')
            cmdline = event.get('CommandLine', '')
            
            # Validate process still exists and is the right one
            self.process_validator.validate(pid, image, cmdline)
            
            # Capture evidence (BEFORE any action)
            memory_dump_path = self._capture_memory(pid)
            registry_snapshot = self._capture_registry(pid)
            process_state = self._capture_process_state(pid)
            
            logger.info(f"Stage5 action {action_id}: Evidence captured")
        except Exception as e:
            logger.error(f"Stage5 action {action_id}: Prepare failed, aborting - {e}")
            return {'status': 'aborted', 'reason': str(e), 'action_id': action_id}
        
        # Step 2: EXECUTE (now perform actual mitigations)
        executed_actions = []
        try:
            # Kill process
            if tier in [RiskTier.CRITICAL, RiskTier.HIGH_HIGH]:
                self.process_killer.kill_process_tree(pid)
                executed_actions.append('process_killed')
            elif tier == RiskTier.HIGH_LOW:
                self.process_killer.suspend_process(pid)
                executed_actions.append('process_suspended')
            
            # Network isolate
            if tier in [RiskTier.CRITICAL, RiskTier.HIGH_HIGH]:
                firewall_rule_id = self.network_isolator.isolate(event)
                executed_actions.append(f'network_isolated_{firewall_rule_id}')
            
            # Quarantine
            if tier == RiskTier.CRITICAL:
                quarantine_path = self.file_quarantine.quarantine_binary(image)
                executed_actions.append(f'quarantined_{quarantine_path}')
            
            logger.info(f"Stage5 action {action_id}: All mitigations succeeded {executed_actions}")
            return {
                'status': 'success',
                'action_id': action_id,
                'actions': executed_actions,
                'evidence': {
                    'memory_dump': memory_dump_path,
                    'registry_snapshot': registry_snapshot,
                    'process_state': process_state
                }
            }
        
        except Exception as e:
            logger.error(f"Stage5 action {action_id}: Execute failed - {e}")
            logger.info(f"Stage5 action {action_id}: Rolling back {len(executed_actions)} actions")
            
            # ROLLBACK all executed actions
            for action in reversed(executed_actions):  # Reverse order
                try:
                    self._rollback_action(action)
                    logger.info(f"Stage5 action {action_id}: Rolled back {action}")
                except Exception as rb_error:
                    logger.error(f"Stage5 action {action_id}: Rollback of {action} failed - {rb_error}")
            
            return {
                'status': 'failed_with_rollback',
                'action_id': action_id,
                'executed_before_failure': executed_actions,
                'reason': str(e)
            }
```

**Files to Create:**
- `src/stage5_mitigation/stage5_engine.py` — Action orchestrator
- `src/stage5_mitigation/action_transaction.py` — Transaction pattern
- `src/stage5_mitigation/rollback_engine.py` — Undo logic

**Effort:** 6 hours  
**Blocker for Stage 5:** YES (CRITICAL for correctness)

---

## Part III: High-Priority Improvements (During Implementation)

### 🟡 HIGH #7: Move Stage 4 Thresholds to Config

**Issue:** Malicious/suspicious thresholds (70/50) hardcoded  
**Solution:** Add to Stage4Config  
**Effort:** 2 hours

---

### 🟡 HIGH #8: Add Graduated Response Model (Confidence-Based)

**Issue:** No escalation if confidence changes  
**Solution:** Confidence-based action selector  
**Effort:** 5 hours

---

### 🟡 HIGH #9: Validate Process Graph vs Kernel State

**Issue:** Graph can grow stale (zombie processes remain)  
**Solution:** Periodic reconciliation with live process list  
**Effort:** 3 hours

---

### 🟡 HIGH #10: Validate Temporal Model Baselines

**Issue:** Baseline poisoning risk (malicious process trains baseline)  
**Solution:** WhiteList validation, poisoning detection  
**Effort:** 4 hours

---

### 🟡 HIGH #11: Add Data Quality Metrics

**Issue:** Cannot debug why feature extraction failed  
**Solution:** Detailed diagnostics in events  
**Effort:** 2 hours

---

### 🟡 HIGH #12: Add Rate Limiting + Backpressure to Stage 5

**Issue:** DOS attack could flood Stage 5  
**Solution:** Max N actions/sec, queue priority, circuit breaker  
**Effort:** 4 hours

---

### 🟡 HIGH #13: Implement Feedback Loop (FP Learning)

**Issue:** False positives don't adjust tier boundaries  
**Solution:** Auto-adjust thresholds based on Stage 4 feedback  
**Effort:** 6 hours

---

### 🟡 HIGH #14: Network Isolation Shadow Mode (Before Hard Block)

**Issue:** Hard network isolation is irreversible timing-wise  
**Solution:** Log-only mode first, then actual block  
**Effort:** 4 hours

---

### 🟡 HIGH #15: Always Capture Forensics (Async)

**Issue:** HIGH tier events lose memory context  
**Solution:** Non-blocking async forensics capture for all tiers  
**Effort:** 3 hours

---

### 🟡 HIGH #16: Implement Disagreement Penalty (Confidence)

**Issue:** Confidence high even when components disagree  
**Solution:** Penalty if ML≠Graph≠Temporal  
**Effort:** 2 hours

---

### 🟡 HIGH #17: Add Correlation IDs (Event Tracing)

**Issue:** Hard to trace decision origin  
**Solution:** UUID on every event from Stage 1  
**Effort:** 2 hours

---

## Part IV: Implementation Timeline

### Execution Phases (Updated with Improvements)

#### **Phase 1A: Foundation & Config (NEW - Blocks everything)**
**Duration:** 2-3 days  
**Tasks:**
- ✋ Critical improvement #1: Move tier boundaries to config
- ✋ Critical improvement #5: Add verdict cache to Stage 4
- ✋ Critical improvement #6: Design Stage 5 as transactions
- ✋ Create `src/ml/schema.py` (centralized feature list)
- ✋ Add Stage5Config to edr_config.py

**Deliverables:**
- Tunable tier thresholds
- Configurable Stage 5 policies
- Verdict consistency guarantee
- Transaction-based action design

---

#### **Phase 1B: Validation & Safety (CRITICAL)**
**Duration:** 3-4 days  
**Tasks:**
- ✋ Critical improvement #2: Triple-check PID before kill
- ✋ Critical improvement #3: Fix YARA handling (context not boost)
- ✋ Critical improvement #4: Split HIGH tier into confidence bands
- ✋ Implement process validation module
- ✋ Implement YARA context separation

**Deliverables:**
- PID validation logic
- YARA context handling
- Confidence-based tier splitting
- Safety baseline

---

#### **Phase 2: Core Stage 5 Implementation**
**Duration:** 5-6 days  
**Tasks:**
- ✅ Implement process containment (kill/suspend/freeze)
- ✅ Implement network isolation (Windows Firewall)
- ✅ Implement file quarantine (safe move pattern)

**Blockers:** Phases 1A + 1B must complete first

---

#### **Phase 3: Rollback + Arbitration**
**Duration:** 5-6 days  
**Tasks:**
- ✅ Implement rollback engine (undo capability)
- ✅ Implement Stage 3/4 arbitration logic
- ✅ Store all actions in database

**Blockers:** Phase 2 must complete first

---

#### **Phase 4: Schema Centralization**
**Duration:** 2-3 days (can run in parallel with Phases 1-2)  
**Tasks:**
- ✅ Create `src/ml/schema.py` (golden feature list)
- ✅ Update all imports to use schema
- ✅ Remove duplicate feature lists
- ✅ Add feature validation

---

#### **Phase 5: Integration & Testing**
**Duration:** 4-5 days  
**Tasks:**
- ✅ Integration tests (HIGH → suspend → downgrade → rollback)
- ✅ Integration tests (CRITICAL → kill → forensics)
- ✅ Load testing (1000+ events/sec)
- ✅ Failure hardening
- ✅ Manual validation on Windows lab VM

---

### Updated Timeline Summary

| Phase | Duration | Blockers | Status |
|-------|----------|----------|--------|
| **1A: Foundation** | 2-3 days | None | ⏳ Ready to start |
| **1B: Validation** | 3-4 days | Needs 1A | ⏳ Ready to start |
| **Phase 2: Core** | 5-6 days | Needs 1A+1B | ⏳ After 1B |
| **Phase 3: Rollback** | 5-6 days | Needs 2 | ⏳ After 2 |
| **Phase 4: Schema** | 2-3 days | None (parallel) | ⏳ Ready to start |
| **Phase 5: Testing** | 4-5 days | Needs 2-3 | ⏳ After 3 |
| **Total** | **24-32 days** | — | **Ready** |

---

## Part V: Summary by Priority Level

### 🔴 CRITICAL (6 issues - MUST FIX BEFORE STAGE 5 CODING)

| # | Issue | Files Affected | Effort | Status |
|---|-------|---|---|---|
| 1 | Tier boundaries hardcoded | `ml_scorer2.py`, `edr_config.py` | 2h | ⏳ Block 1A |
| 2 | PID reuse risk | New `process_validation.py` | 3h | ⏳ Block 1B |
| 3 | YARA score boost wrong | `yara_scanner.py`, `stage3_engine.py` | 4h | ⏳ Block 1B |
| 4 | HIGH tier too aggressive | `stage3_engine.py`, `ml_scorer2.py` | 5h | ⏳ Block 1B |
| 5 | Stage 4 no verdict cache | `stage4_engine.py` | 3h | ⏳ Block 1A |
| 6 | No atomic actions | New `stage5_engine.py` | 6h | ⏳ Block 1B |
| | **Subtotal** | — | **23h** | **Complete in 1A+1B** |

### 🟡 HIGH (11 issues - DURING IMPLEMENTATION)

| # | Issue | Effort | Integration Point |
|---|---|---|---|
| 7 | Stage 4 thresholds to config | 2h | Phase 1A |
| 8 | Confidence-based escalation | 5h | Phase 1B |
| 9 | Graph state validation | 3h | Phase 2 |
| 10 | Baseline poisoning detection | 4h | Phase 2 |
| 11 | Data quality metrics | 2h | Phase 4 |
| 12 | Rate limiting + backpressure | 4h | Phase 2 |
| 13 | Feedback loop (FP learning) | 6h | Phase 5 |
| 14 | Network shadow mode | 4h | Phase 2 |
| 15 | Forensics capture async | 3h | Phase 2 |
| 16 | Disagreement penalty | 2h | Phase 1B |
| 17 | Correlation IDs | 2h | Phase 4 |
| | **Subtotal** | **38h** | **Spread across phases** |

### 🟢 LOW (7 issues - POST-IMPLEMENTATION)

- Stage transition metering
- Chaos fault injection testing
- Rule consolidation refactor
- Process cleanup determinism
- Feature diagnostics dashboard
- Error handling uniformity
- Configuration persistence

---

## Part VI: Decision Checklist

### Before Starting Phase 1A, Approve:

- [ ] **Decision 1:** Use strict PID validation (triple-check) or fast validation?
  - Recommended: ✅ Strict (security > speed for kill operations)

- [ ] **Decision 2:** YARA as context only (no score boost) or keep light boost?
  - Recommended: ✅ Context only (behavioral signals more reliable)

- [ ] **Decision 3:** Verdict cache per-PID or per-ProcessName?
  - Recommended: ✅ Per-PID with 5-min TTL (consistency + freshness)

- [ ] **Decision 4:** Graduated response (multiple HIGH tiers) or simple HIGH?
  - Recommended: ✅ Graduated (HIGH_LOW + HIGH_HIGH + CRITICAL = 3-tier)

- [ ] **Decision 5:** Rate limit Stage 5 actions or unlimited?
  - Recommended: ✅ Rate limit (max 100 actions/sec, queue priority)

- [ ] **Decision 6:** Network isolation mode first or hard block?
  - Recommended: ✅ Shadow mode first (5min observation, then block)

---

## Part VII: Success Criteria

### Functional Requirements
- [ ] Stage 5 processes HIGH tier: suspend or suspend+isolate (based on confidence)
- [ ] Stage 5 processes CRITICAL tier: kill + quarantine + forensics
- [ ] Network isolation rules removed on downgrade
- [ ] Quarantined files restored with hash verification
- [ ] Process restart attempted on downgrade (whitelist checks)
- [ ] All actions logged with correlation IDs
- [ ] Dashboard shows action timeline

### Non-Functional Requirements
- [ ] Stage 5 adds < 100ms latency per action
- [ ] No Stage 5 failure crashes entire pipeline
- [ ] Train/inference feature set consistency validated
- [ ] Schema centralization reduces hardcoded lists (5 places → 1)
- [ ] System handles 1000+ events/sec without backlog

### Testing Requirements
- [ ] Unit tests for all 6 Stage 5 improvements
- [ ] Integration: HIGH → suspend → downgrade → rollback
- [ ] Integration: CRITICAL → kill → forensics → Stage 4 forward
- [ ] Load test: 1000 events/sec through pipeline
- [ ] Manual validation on Windows lab VM
- [ ] Chaos injection tests (simulate failures)

---

## Part VIII: Risk Mitigation

| Risk | Mitigation | Effort |
|------|-----------|--------|
| Kill wrong process (PID reuse) | Triple validation (Critical #2) | 3h |
| False positive harms business | Graduated response (Critical #4) | 5h |
| Network isolation irreversible | Shadow mode (High #14) | 4h |
| Rollback incomplete | Atomic actions (Critical #6) | 6h |
| Evidence loss | Always capture forensics (High #15) | 3h |
| DOS attack on Stage 5 | Rate limiting (High #12) | 4h |
| Performance degradation | Async Stage 5, no blocking (Phases 2-3) | Built-in |

---

## Next Steps

### ✅ Completed
- [x] Architecture review (comprehensive)
- [x] Current state documentation (Stages 1-4)
- [x] Improvement opportunities identified (24 total)
- [x] Critical issues prioritized (6 blocking)
- [x] Implementation plan created (5 phases)

### ⏭️ Ready to Start

1. **Approve decisions** (Section VI) — 15 min
2. **Create Phase 1A tasks** (config + centralization) — 2-3 days
3. **Create Phase 1B tasks** (validation + safety) — 3-4 days
4. **Begin Phase 2** (core Stage 5) after 1A+1B complete

---

**Document Status:** ✅ FINALIZED & READY FOR IMPLEMENTATION

**Last Updated:** April 13, 2026  
**Next Review:** After Phase 1B completion
