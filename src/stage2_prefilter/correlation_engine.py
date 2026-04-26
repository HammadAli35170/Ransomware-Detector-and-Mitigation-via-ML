"""
Cross-PID Correlation Engine for Coordinated Attack Detection

Detects coordinated ransomware activities across multiple processes:
- Parent-child process chains with suspicious behavior
- Multiple processes accessing same files/directories
- Temporal correlation of suspicious activities
- Process spawning patterns
"""

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
import logging

logger = logging.getLogger("correlation_engine")


@dataclass
class ProcessActivity:
    """Tracks activity pattern for a process"""
    pid: int
    parent_pid: Optional[int]
    image_path: str
    first_seen: float
    last_seen: float
    suspicious_score: float = 0.0
    files_touched: Set[str] = field(default_factory=set)
    directories_touched: Set[str] = field(default_factory=set)
    event_types: Set[str] = field(default_factory=set)
    suspicious_flags: List[str] = field(default_factory=list)


@dataclass
class CorrelationPattern:
    """Represents a detected correlation pattern"""
    pattern_type: str  # "parent_child", "file_sharing", "temporal", "spawn_chain"
    pids: List[int]
    confidence: float
    evidence: Dict[str, Any]
    detected_at: float


class CorrelationEngine:
    """
    Detects coordinated ransomware activities across multiple processes.
    """
    
    def __init__(self, window_sec: int = 300, cleanup_sec: int = 600):
        """
        Args:
            window_sec: Time window for correlation analysis (default 5 minutes)
            cleanup_sec: Cleanup processes older than this (default 10 minutes)
        """
        self.window_sec = float(window_sec)
        self.cleanup_sec = float(cleanup_sec)
        self._lock = threading.RLock()
        
        # Process activity tracking
        self.processes: Dict[int, ProcessActivity] = {}
        
        # File/directory sharing tracking: file -> set of PIDs
        self.file_accessors: Dict[str, Set[int]] = defaultdict(set)
        self.dir_accessors: Dict[str, Set[int]] = defaultdict(set)
        
        # Parent-child relationships
        self.children: Dict[int, Set[int]] = defaultdict(set)  # parent_pid -> set of child_pids
        
        # Detected correlation patterns
        self.patterns: deque = deque(maxlen=1000)
        
        # Performance optimization: track recent file accesses (last 60 seconds)
        self.recent_file_accesses: deque = deque(maxlen=10000)  # (timestamp, pid, filepath)
        self.recent_dir_accesses: deque = deque(maxlen=10000)   # (timestamp, pid, dirpath)
        
        logger.info(f"CorrelationEngine initialized (window={window_sec}s, cleanup={cleanup_sec}s)")
    
    def update_process_activity(
        self,
        pid: int,
        parent_pid: Optional[int] = None,
        image_path: str = "",
        filepath: Optional[str] = None,
        event_type: str = "",
        suspicious_score: float = 0.0,
        suspicious_flags: Optional[List[str]] = None
    ) -> None:
        """Update process activity tracking"""
        now = time.time()
        
        with self._lock:
            if pid not in self.processes:
                self.processes[pid] = ProcessActivity(
                    pid=pid,
                    parent_pid=parent_pid,
                    image_path=image_path,
                    first_seen=now,
                    last_seen=now
                )
            
            pa = self.processes[pid]
            pa.last_seen = now
            if parent_pid is not None:
                pa.parent_pid = parent_pid
            if image_path:
                pa.image_path = image_path
            pa.suspicious_score += suspicious_score
            
            if filepath:
                pa.files_touched.add(filepath)
                # Track file accessors for correlation
                self.file_accessors[filepath].add(pid)
                self.recent_file_accesses.append((now, pid, filepath))
                
                # Track directory
                from pathlib import Path
                try:
                    dirpath = str(Path(filepath).parent)
                    pa.directories_touched.add(dirpath)
                    self.dir_accessors[dirpath].add(pid)
                    self.recent_dir_accesses.append((now, pid, dirpath))
                except Exception:
                    pass
            
            if event_type:
                pa.event_types.add(event_type)
            
            if suspicious_flags:
                pa.suspicious_flags.extend(suspicious_flags)
            
            # Update parent-child relationship
            if parent_pid is not None and parent_pid != pid:
                self.children[parent_pid].add(pid)
    
    def detect_correlations(self, pid: int) -> List[CorrelationPattern]:
        """
        Detect correlation patterns involving the given PID.
        Returns list of detected patterns.
        """
        patterns = []
        now = time.time()
        
        with self._lock:
            if pid not in self.processes:
                return patterns
            
            pa = self.processes[pid]
            
            # Pattern 1: Parent-child chain with suspicious activity
            parent_chain_pattern = self._detect_parent_child_pattern(pid)
            if parent_chain_pattern:
                patterns.append(parent_chain_pattern)
            
            # Pattern 2: Multiple processes accessing same files
            file_sharing_pattern = self._detect_file_sharing_pattern(pid)
            if file_sharing_pattern:
                patterns.append(file_sharing_pattern)
            
            # Pattern 3: Temporal correlation (multiple suspicious processes in short time window)
            temporal_pattern = self._detect_temporal_correlation(pid, now)
            if temporal_pattern:
                patterns.append(temporal_pattern)
            
            # Pattern 4: Rapid process spawning chain
            spawn_chain_pattern = self._detect_spawn_chain_pattern(pid)
            if spawn_chain_pattern:
                patterns.append(spawn_chain_pattern)
        
        # Store detected patterns
        for pattern in patterns:
            self.patterns.append(pattern)
        
        return patterns
    
    def _detect_parent_child_pattern(self, pid: int) -> Optional[CorrelationPattern]:
        """Detect suspicious parent-child process chains"""
        pa = self.processes[pid]
        
        # Check if parent is also suspicious
        if pa.parent_pid and pa.parent_pid in self.processes:
            parent_pa = self.processes[pa.parent_pid]
            
            # Both parent and child have suspicious activity
            if parent_pa.suspicious_score > 5.0 and pa.suspicious_score > 5.0:
                # Calculate confidence based on activity overlap
                shared_dirs = parent_pa.directories_touched & pa.directories_touched
                confidence = min(0.9, 0.5 + (len(shared_dirs) * 0.1))
                
                return CorrelationPattern(
                    pattern_type="parent_child",
                    pids=[pa.parent_pid, pid],
                    confidence=confidence,
                    evidence={
                        "parent_score": parent_pa.suspicious_score,
                        "child_score": pa.suspicious_score,
                        "shared_directories": len(shared_dirs),
                        "parent_image": parent_pa.image_path,
                        "child_image": pa.image_path
                    },
                    detected_at=time.time()
                )
        
        return None
    
    def _detect_file_sharing_pattern(self, pid: int) -> Optional[CorrelationPattern]:
        """Detect multiple processes accessing same files/directories"""
        pa = self.processes[pid]
        
        # Check files touched by this process
        for filepath in list(pa.files_touched)[:10]:  # Limit to first 10 for performance
            accessors = self.file_accessors.get(filepath, set())
            if len(accessors) > 1:  # Multiple processes accessing same file
                other_pids = [p for p in accessors if p != pid]
                
                # Check if other accessors are also suspicious
                suspicious_others = [
                    p for p in other_pids
                    if p in self.processes and self.processes[p].suspicious_score > 3.0
                ]
                
                if suspicious_others:
                    confidence = min(0.85, 0.4 + (len(suspicious_others) * 0.15))
                    
                    return CorrelationPattern(
                        pattern_type="file_sharing",
                        pids=[pid] + suspicious_others[:5],  # Limit to 5 PIDs
                        confidence=confidence,
                        evidence={
                            "shared_file": filepath,
                            "accessor_count": len(accessors),
                            "suspicious_accessors": len(suspicious_others)
                        },
                        detected_at=time.time()
                    )
        
        return None
    
    def _detect_temporal_correlation(self, pid: int, now: float) -> Optional[CorrelationPattern]:
        """Detect multiple suspicious processes appearing in short time window"""
        pa = self.processes[pid]
        
        if pa.suspicious_score < 5.0:
            return None
        
        # Find other suspicious processes in the last 60 seconds
        time_window = 60.0
        correlated_pids = []
        
        for other_pid, other_pa in self.processes.items():
            if other_pid == pid:
                continue
            
            time_diff = abs(other_pa.first_seen - pa.first_seen)
            if time_diff <= time_window and other_pa.suspicious_score > 5.0:
                # Check for shared directories (stronger correlation)
                shared_dirs = pa.directories_touched & other_pa.directories_touched
                if shared_dirs or time_diff <= 10.0:  # Within 10 seconds or share directories
                    correlated_pids.append(other_pid)
        
        if len(correlated_pids) >= 2:  # At least 3 processes total (including current)
            confidence = min(0.8, 0.3 + (len(correlated_pids) * 0.1))
            
            return CorrelationPattern(
                pattern_type="temporal",
                pids=[pid] + correlated_pids[:4],  # Limit to 5 PIDs total
                confidence=confidence,
                evidence={
                    "process_count": len(correlated_pids) + 1,
                    "time_window_sec": time_window,
                    "suspicious_scores": {
                        str(p): self.processes[p].suspicious_score
                        for p in [pid] + correlated_pids[:4]
                        if p in self.processes
                    }
                },
                detected_at=now
            )
        
        return None
    
    def _detect_spawn_chain_pattern(self, pid: int) -> Optional[CorrelationPattern]:
        """Detect rapid process spawning chain (ransomware often spawns multiple workers)"""
        spawn_chain = [pid]
        current_pid = pid
        
        # Follow parent chain
        for _ in range(5):  # Max depth of 5
            if current_pid not in self.processes:
                break
            
            pa = self.processes[current_pid]
            if pa.parent_pid is None:
                break
            
            parent_pid = pa.parent_pid
            if parent_pid in spawn_chain:  # Cycle detected
                break
            
            spawn_chain.append(parent_pid)
            current_pid = parent_pid
        
        # Check if chain has multiple suspicious processes
        suspicious_in_chain = [
            p for p in spawn_chain
            if p in self.processes and self.processes[p].suspicious_score > 5.0
        ]
        
        if len(spawn_chain) >= 3 and len(suspicious_in_chain) >= 2:
            # Check spawn timing (rapid spawning is suspicious)
            spawn_times = [
                self.processes[p].first_seen for p in spawn_chain
                if p in self.processes
            ]
            if spawn_times:
                spawn_duration = max(spawn_times) - min(spawn_times)
                if spawn_duration <= 30.0:  # Spawned within 30 seconds
                    confidence = min(0.9, 0.5 + (3.0 / max(spawn_duration, 1.0)) * 0.1)
                    
                    return CorrelationPattern(
                        pattern_type="spawn_chain",
                        pids=spawn_chain,
                        confidence=confidence,
                        evidence={
                            "chain_length": len(spawn_chain),
                            "spawn_duration_sec": spawn_duration,
                            "suspicious_count": len(suspicious_in_chain)
                        },
                        detected_at=time.time()
                    )
        
        return None
    
    def cleanup_old_processes(self) -> None:
        """Remove processes older than cleanup_sec"""
        now = time.time()
        
        with self._lock:
            to_remove = []
            for pid, pa in self.processes.items():
                if now - pa.last_seen > self.cleanup_sec:
                    to_remove.append(pid)
            
            for pid in to_remove:
                pa = self.processes[pid]
                # Remove from file/directory accessors
                for filepath in pa.files_touched:
                    self.file_accessors[filepath].discard(pid)
                    if not self.file_accessors[filepath]:
                        del self.file_accessors[filepath]
                
                for dirpath in pa.directories_touched:
                    self.dir_accessors[dirpath].discard(pid)
                    if not self.dir_accessors[dirpath]:
                        del self.dir_accessors[dirpath]
                
                # Remove from children tracking
                if pid in self.children:
                    del self.children[pid]
                for parent_pid, children_set in self.children.items():
                    children_set.discard(pid)
                
                del self.processes[pid]
            
            if to_remove:
                logger.debug(f"CorrelationEngine: Cleaned up {len(to_remove)} old processes")
    
    def get_correlation_summary(self, pid: int) -> Dict[str, Any]:
        """Get correlation summary for a PID"""
        patterns = self.detect_correlations(pid)
        
        return {
            "pid": pid,
            "patterns_detected": len(patterns),
            "pattern_types": [p.pattern_type for p in patterns],
            "max_confidence": max([p.confidence for p in patterns], default=0.0),
            "correlated_pids": list(set(
                pid for p in patterns for pid in p.pids if pid != pid
            )),
            "patterns": [
                {
                    "type": p.pattern_type,
                    "confidence": p.confidence,
                    "pids": p.pids,
                    "evidence": p.evidence
                }
                for p in patterns
            ]
        }


# Global correlation engine instance
_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    """Get the global correlation engine instance"""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine

