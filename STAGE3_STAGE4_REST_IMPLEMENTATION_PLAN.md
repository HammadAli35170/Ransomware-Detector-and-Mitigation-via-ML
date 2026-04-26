# RDNXSYS Stage 3 and Stage 4 Focused Implementation Plan

Last Updated: April 13, 2026
Scope: Remaining implementation with current focus on Stage 3 and Stage 4 only

## 1) Goal of This Plan

Build and harden two separate ML models with clear responsibilities:
- Stage 3 model: ultra-fast, high-recall ransomware detector for low-latency inline decisions.
- Stage 4 model: temporal, context-rich, in-depth confirmer for precision and override.

This plan intentionally defers full Stage 5 implementation details except for required interfaces from Stage 3 and Stage 4 outputs.

## 2) Current Status Snapshot

### Already Implemented
- Stage 3 scoring path with tiering exists.
- Stage 4 deep analysis pipeline exists (graph, temporal, rules, ML classifier wrapper).
- Tier boundaries are now configurable via central config.
- Stage 3 HIGH band split exists:
  - high_low (80-87)
  - high_high (88-94)
- Stage 4 verdict cache scaffolding exists with TTL and max-size controls.
- Dataset generator v4 has been hardened and aligned toward single-source use.

### Recently Hardened
- Stage 3 tier thresholds are config-driven.
- Stage 4 verdict caching is in place.
- Stage 3 HIGH band split policy is in place and event annotations are emitted.

## 3) Final Target Architecture (Stage 3 + Stage 4)

### Stage 3 Model (Model A)
Purpose: Fast gate and fast containment trigger.
- Input: per-event and short-window feature vector (fixed schema).
- Output:
  - score_0_100
  - tier low/medium/high/critical
  - high_band high_low/high_high for high tier
- Optimization objective:
  - maximize recall under strict latency budget
  - maintain bounded false positives through Stage 4 handoff

### Stage 4 Model (Model B)
Purpose: Temporal and context-rich confirmation/override.
- Input:
  - Stage 3 features and score context
  - graph features
  - temporal sequence features
  - rule evidence
- Output:
  - verdict malicious/suspicious/benign/unknown
  - confidence
  - reasoning components for explainability
- Optimization objective:
  - maximize precision and calibration
  - stable override behavior for Stage 3 high_low cases

## 4) Model Separation Rules (Must Keep)

- Never share thresholds between Stage 3 and Stage 4 directly.
- Never train Stage 4 to replicate Stage 3 score as target.
- Stage 3 remains latency-first and recall-first.
- Stage 4 remains context-first and precision-first.
- Stage 4 can downgrade Stage 3 decisions, but Stage 3 remains independent at inference time.

## 5) Data Contract and Single Source of Truth

Canonical generator source:
- Modifications/dataset_generator_v4_complete.py

Produced artifacts (canonical contract):
- raw_events.parquet
- stage3_dataset.parquet
- stage4_sequences.parquet
- dataset_config.json

Contract rules:
- Feature list hash must match between train and inference.
- Split assignment must remain deterministic and leakage-safe.
- Stage 3 training uses stage3_dataset only.
- Stage 4 training uses stage4_sequences plus context labels.

## 6) Remaining Implementation Work

## Phase A: Stage 3 Model Finalization

1. Training pipeline hardening
- Finalize Stage 3 trainer to consume stage3_dataset only.
- Add strict schema hash check before training starts.
- Add class imbalance handling suitable for SOC profile.

2. Objective and threshold calibration
- Tune for high recall and stable medium/high transition.
- Validate high_band_split_score with precision-recall sweeps.
- Produce final thresholds in config, not code.

3. Explainability and diagnostics
- Export top feature importances per run.
- Add per-tier confusion summaries.
- Add calibration bins for score reliability.

4. Runtime alignment checks
- On model load, verify expected feature order and hash.
- Fail fast on mismatch.

Deliverables:
- stage3_model_vNext
- stage3_model_vNext.config.json
- stage3_model_vNext.evaluation_report.txt
- stage3_model_vNext.importance.json

## Phase B: Stage 4 Model Finalization

1. Sequence model training pipeline
- Build dedicated Stage 4 trainer for stage4_sequences.
- Parse sequence_features and sequence_mask consistently.
- Train temporal/context model separate from Stage 3 artifacts.

2. Multi-component decision calibration
- Calibrate fusion weights between ML, graph, temporal, and rules.
- Calibrate malicious and suspicious thresholds from validation set.
- Validate downgrade/upgrade stability against Stage 3 high bands.

3. Confidence quality and agreement
- Add disagreement penalty when components diverge strongly.
- Validate confidence calibration (reliability curves).
- Add drift checks for temporal feature distributions.

4. Cache behavior validation
- Verify verdict cache TTL behavior under repeated PID events.
- Confirm no stale verdict leakage beyond TTL.

Deliverables:
- stage4_model_vNext
- stage4_model_vNext.config.json
- stage4_model_vNext.evaluation_report.txt
- stage4_model_vNext.calibration.json

## Phase C: Stage 3 to Stage 4 Integration Hardening

1. Handoff policy finalization
- medium always to Stage 4.
- high_low immediate response plus Stage 4 confirmation.
- high_high immediate response only, optional forensics path to Stage 4.
- critical immediate response plus Stage 4 forensics.

2. Event annotation contract
- Enforce required fields:
  - __stage3_score
  - __stage3_tier
  - __stage3_high_band (for high)
  - __stage3_features

3. Metrics and dashboards
- Add stage transition counters and rates.
- Add per-band outcomes (high_low vs high_high).
- Add Stage 4 cache hit/miss observability.

Deliverables:
- stable handoff policy document in config
- stage transition metric outputs available at runtime

## 7) Acceptance Criteria

Stage 3 acceptance:
- Meets latency budget under load.
- Recall target met on held-out test set.
- Feature contract mismatch is blocked at runtime.
- Thresholds are fully config-driven.

Stage 4 acceptance:
- Precision and calibration targets met on held-out test set.
- Temporal/context model materially improves false-positive control.
- Cache behavior is correct and bounded.

Integration acceptance:
- high_low and high_high paths behave as designed.
- Stage 4 downgrade behavior is stable and explainable.
- No data leakage detected in split validation.

## 8) Risks and Mitigations

Risk: Stage 3 overfits synthetic artifacts.
Mitigation: stronger overlap/evasion settings and out-of-distribution checks.

Risk: Stage 4 learns Stage 3 score shortcut.
Mitigation: ablation tests and restricted feature influence checks.

Risk: Schema drift breaks inference silently.
Mitigation: strict hash check and fail-fast startup.

Risk: Cache returns stale Stage 4 verdict.
Mitigation: conservative TTL and cleanup on schedule.

## 9) Immediate Next Steps

1. Finalize Stage 3 trainer runbook and produce vNext candidate model.
2. Create dedicated Stage 4 sequence trainer and baseline model.
3. Run joint evaluation matrix by Stage 3 tier and high band.
4. Lock config defaults for thresholds and cache values.

## 10) Out of Scope for This Document

- Full Stage 5 mitigation action implementation.
- Kernel-level protection and enterprise orchestration.
- SOC workflow automation beyond Stage 3/4 outputs.
