"""
Decision Engine for Stage 4

Combines all analysis results (graph, temporal, ML, rules) to make
final classification decision with confidence scoring.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

from .ml_classifier import ClassificationResult
from .rule_engine import RuleMatch, RulePriority

logger = logging.getLogger("stage4_decision_engine")


class FinalVerdict(Enum):
    """Final classification verdict"""
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"  # Between unknown and malicious


@dataclass
class DecisionResult:
    """Final decision from Stage 4"""
    verdict: FinalVerdict
    confidence: float  # 0.0 to 1.0
    score: float  # Combined score 0-100
    
    # Component scores
    ml_score: float = 0.0
    graph_score: float = 0.0
    temporal_score: float = 0.0
    rule_score: float = 0.0
    
    # Details
    ml_result: Optional[ClassificationResult] = None
    rule_matches: List[RuleMatch] = None
    reasoning: List[str] = None
    
    # Flags
    rule_override: bool = False  # Rules overrode ML decision
    requires_sandbox: bool = False  # Should trigger sandbox analysis
    requires_threat_intel: bool = False  # Should check threat intelligence


class DecisionEngine:
    """
    Decision engine that combines all Stage 4 analysis results.
    
    Multi-factor scoring:
    - ML classification (weighted)
    - Graph analytics (weighted)
    - Temporal analysis (weighted)
    - Rule matches (can override)
    """
    
    def __init__(
        self,
        ml_weight: float = 0.4,
        graph_weight: float = 0.25,
        temporal_weight: float = 0.25,
        rule_weight: float = 0.1,
        malicious_threshold: float = 70.0,
        suspicious_threshold: float = 50.0,
        unknown_threshold: float = 30.0
    ):
        """
        Initialize Decision Engine.
        
        Args:
            ml_weight: Weight for ML classifier (default 0.4)
            graph_weight: Weight for graph analysis (default 0.25)
            temporal_weight: Weight for temporal analysis (default 0.25)
            rule_weight: Weight for rule matches (default 0.1)
            malicious_threshold: Score threshold for malicious (default 70.0)
            suspicious_threshold: Score threshold for suspicious (default 50.0)
            unknown_threshold: Score threshold below which is unknown (default 30.0)
        """
        self.ml_weight = ml_weight
        self.graph_weight = graph_weight
        self.temporal_weight = temporal_weight
        self.rule_weight = rule_weight
        
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold
        self.unknown_threshold = unknown_threshold
        
        logger.info("DecisionEngine initialized")
    
    def make_decision(
        self,
        ml_result: ClassificationResult,
        graph_metrics: Dict[str, float],
        temporal_metrics: Dict[str, float],
        rule_matches: List[RuleMatch],
        stage3_score: float = 0.0
    ) -> DecisionResult:
        """
        Make final decision based on all analysis results.
        
        Args:
            ml_result: ML classification result
            graph_metrics: Graph analysis metrics
            temporal_metrics: Temporal analysis metrics
            rule_matches: Rule engine matches
            stage3_score: Score from Stage 3 (for context)
            
        Returns:
            DecisionResult with final verdict
        """
        reasoning = []
        
        # Calculate component scores (0-100)
        ml_score = self._ml_to_score(ml_result)
        graph_score = self._graph_to_score(graph_metrics)
        temporal_score = self._temporal_to_score(temporal_metrics)
        rule_score = self._rules_to_score(rule_matches)
        
        # Check for rule override
        rule_override = False
        if rule_matches:
            highest_priority = min(rule_matches, key=lambda x: x.priority.value)
            if highest_priority.priority in [RulePriority.CRITICAL, RulePriority.HIGH]:
                if highest_priority.matched:
                    rule_override = True
                    reasoning.append(f"Critical rule match: {highest_priority.rule_name}")
        
        # Weighted combination
        if rule_override and rule_score > 80:
            # Rules override ML for critical matches
            combined_score = (
                rule_score * 0.6 +
                ml_score * 0.2 +
                graph_score * 0.1 +
                temporal_score * 0.1
            )
            reasoning.append("Rule override applied")
        else:
            # Normal weighted combination
            combined_score = (
                ml_score * self.ml_weight +
                graph_score * self.graph_weight +
                temporal_score * self.temporal_weight +
                rule_score * self.rule_weight
            )
        
        # Incorporate Stage 3 score (10% influence)
        if stage3_score > 0:
            combined_score = combined_score * 0.9 + (stage3_score * 0.1)
        
        # Determine verdict
        if combined_score >= self.malicious_threshold:
            verdict = FinalVerdict.MALICIOUS
            reasoning.append(f"High combined score: {combined_score:.2f}")
        elif combined_score >= self.suspicious_threshold:
            verdict = FinalVerdict.SUSPICIOUS
            reasoning.append(f"Moderate score: {combined_score:.2f}")
        elif combined_score >= self.unknown_threshold:
            verdict = FinalVerdict.UNKNOWN
            reasoning.append(f"Low confidence: {combined_score:.2f}")
        else:
            verdict = FinalVerdict.BENIGN
            reasoning.append(f"Low score indicates benign: {combined_score:.2f}")
        
        # Calculate confidence (based on agreement between components)
        confidence = self._calculate_confidence(
            ml_score, graph_score, temporal_score, rule_score
        )
        
        # Determine if sandbox or threat intel needed
        requires_sandbox = (
            verdict == FinalVerdict.UNKNOWN and
            combined_score > 40.0 and
            ml_result.confidence < 0.6
        )
        
        requires_threat_intel = (
            verdict in [FinalVerdict.SUSPICIOUS, FinalVerdict.MALICIOUS] and
            combined_score > 60.0
        )
        
        return DecisionResult(
            verdict=verdict,
            confidence=confidence,
            score=combined_score,
            ml_score=ml_score,
            graph_score=graph_score,
            temporal_score=temporal_score,
            rule_score=rule_score,
            ml_result=ml_result,
            rule_matches=rule_matches,
            reasoning=reasoning,
            rule_override=rule_override,
            requires_sandbox=requires_sandbox,
            requires_threat_intel=requires_threat_intel
        )
    
    def _ml_to_score(self, ml_result: ClassificationResult) -> float:
        """Convert ML result to 0-100 score"""
        if ml_result.prediction == "malicious":
            return ml_result.confidence * 100.0
        elif ml_result.prediction == "benign":
            return (1.0 - ml_result.confidence) * 100.0
        else:  # unknown
            return 50.0  # Neutral score
    
    def _graph_to_score(self, metrics: Dict[str, float]) -> float:
        """Convert graph metrics to 0-100 score"""
        score = 0.0
        
        # Relationship anomalies
        if metrics.get('relationship_anomaly_score', 0) > 5:
            score += 20.0
        
        # Unusual patterns
        if metrics.get('unusual_parent', False):
            score += 15.0
        if metrics.get('unusual_spawning_pattern', False):
            score += 15.0
        
        # High centrality (suspicious if isolated but central)
        if metrics.get('centrality_score', 0) > 0.5 and metrics.get('isolated_process', False):
            score += 10.0
        
        # High network/file degree
        if metrics.get('network_degree', 0) > 10:
            score += 10.0
        if metrics.get('file_access_degree', 0) > 50:
            score += 15.0
        
        return min(100.0, score)
    
    def _temporal_to_score(self, metrics: Dict[str, float]) -> float:
        """Convert temporal metrics to 0-100 score"""
        score = 0.0
        
        # Baseline deviation
        if metrics.get('baseline_deviation_score', 0) > 5:
            score += 20.0
        
        # Pattern matching
        if metrics.get('pattern_match_score', 0) > 5:
            score += 25.0
        
        # Time series anomalies
        if metrics.get('time_series_anomaly', 0) > 5:
            score += 15.0
        
        # Entropy trend
        if metrics.get('entropy_trend', 0) > 1.0:
            score += 15.0
        
        # Burst detection
        if metrics.get('burst_detection_score', 0) > 7:
            score += 15.0
        
        # I/O acceleration
        if metrics.get('io_acceleration', 0) > 2.0:
            score += 10.0
        
        return min(100.0, score)
    
    def _rules_to_score(self, matches: List[RuleMatch]) -> float:
        """Convert rule matches to 0-100 score"""
        if not matches:
            return 0.0
        
        score = 0.0
        for match in matches:
            if match.matched:
                if match.priority == RulePriority.CRITICAL:
                    score += 40.0
                elif match.priority == RulePriority.HIGH:
                    score += 25.0
                elif match.priority == RulePriority.MEDIUM:
                    score += 15.0
                else:
                    score += 5.0
        
        return min(100.0, score)
    
    def _calculate_confidence(
        self,
        ml_score: float,
        graph_score: float,
        temporal_score: float,
        rule_score: float
    ) -> float:
        """
        Calculate confidence based on agreement between components.
        Higher agreement = higher confidence.
        """
        scores = [ml_score, graph_score, temporal_score, rule_score]
        scores = [s for s in scores if s > 0]  # Remove zero scores
        
        if not scores:
            return 0.0
        
        # Calculate variance (lower variance = higher agreement)
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        
        # Convert variance to confidence (inverse relationship)
        # Normalize variance to 0-1, then invert
        max_variance = 10000.0  # Max possible variance for 0-100 scores
        normalized_variance = min(1.0, variance / max_variance)
        confidence = 1.0 - normalized_variance
        
        # Boost confidence if all components agree (all high or all low)
        if all(s > 60 for s in scores) or all(s < 40 for s in scores):
            confidence = min(1.0, confidence * 1.2)
        
        return confidence

