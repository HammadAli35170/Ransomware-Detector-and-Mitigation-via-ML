"""
Performance Monitor

Tracks timing metrics and throughput across all stages for performance analysis.
"""

import time
import threading
from typing import Dict, Any, Optional, List
from collections import deque, defaultdict
from dataclasses import dataclass, field
import logging

logger = logging.getLogger("performance_monitor")


@dataclass
class TimingMetrics:
    """Timing metrics for a single operation"""
    stage: str
    operation: str
    duration_sec: float
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceMonitor:
    """
    Performance monitor that tracks timing and throughput metrics across stages.
    
    Thread-safe and designed for high-throughput scenarios.
    """
    
    def __init__(self, max_samples: int = 10000, window_sec: float = 300.0):
        """
        Args:
            max_samples: Maximum number of timing samples to keep in memory
            window_sec: Time window for calculating throughput (default 5 minutes)
        """
        self.max_samples = max_samples
        self.window_sec = window_sec
        self._lock = threading.RLock()
        
        # Timing samples (FIFO queue)
        self._timing_samples: deque = deque(maxlen=max_samples)
        
        # Stage statistics
        self._stage_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total_operations": 0,
            "total_duration_sec": 0.0,
            "successful_operations": 0,
            "failed_operations": 0,
            "min_duration_sec": float('inf'),
            "max_duration_sec": 0.0,
            "last_operation_time": 0.0,
        })
        
        # Operation-level statistics
        self._operation_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "count": 0,
            "total_duration_sec": 0.0,
            "success_count": 0,
            "fail_count": 0,
        })
    
    def record_timing(
        self,
        stage: str,
        operation: str,
        duration_sec: float,
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record a timing measurement.
        
        Args:
            stage: Stage name (e.g., "stage1", "stage2", "stage3")
            operation: Operation name (e.g., "normalize", "extract_features", "ml_score")
            duration_sec: Duration in seconds
            success: Whether the operation succeeded
            metadata: Optional metadata dictionary
        """
        with self._lock:
            # Create timing sample
            sample = TimingMetrics(
                stage=stage,
                operation=operation,
                duration_sec=duration_sec,
                timestamp=time.time(),
                success=success,
                metadata=metadata or {}
            )
            self._timing_samples.append(sample)
            
            # Update stage statistics
            stage_key = f"{stage}"
            stats = self._stage_stats[stage_key]
            stats["total_operations"] += 1
            stats["total_duration_sec"] += duration_sec
            stats["last_operation_time"] = sample.timestamp
            if success:
                stats["successful_operations"] += 1
            else:
                stats["failed_operations"] += 1
            stats["min_duration_sec"] = min(stats["min_duration_sec"], duration_sec)
            stats["max_duration_sec"] = max(stats["max_duration_sec"], duration_sec)
            
            # Update operation statistics
            op_key = f"{stage}.{operation}"
            op_stats = self._operation_stats[op_key]
            op_stats["count"] += 1
            op_stats["total_duration_sec"] += duration_sec
            if success:
                op_stats["success_count"] += 1
            else:
                op_stats["fail_count"] += 1
    
    def get_stage_metrics(self, stage: str) -> Dict[str, Any]:
        """
        Get performance metrics for a specific stage.
        
        Args:
            stage: Stage name
            
        Returns:
            Dictionary with performance metrics
        """
        with self._lock:
            stats = self._stage_stats.get(stage, {})
            if not stats or stats["total_operations"] == 0:
                return {
                    "stage": stage,
                    "total_operations": 0,
                    "avg_duration_sec": 0.0,
                    "min_duration_sec": 0.0,
                    "max_duration_sec": 0.0,
                    "success_rate": 0.0,
                    "throughput_per_sec": 0.0,
                }
            
            total_ops = stats["total_operations"]
            avg_duration = stats["total_duration_sec"] / total_ops if total_ops > 0 else 0.0
            success_rate = (stats["successful_operations"] / total_ops * 100) if total_ops > 0 else 0.0
            
            # Calculate throughput (operations per second in recent window)
            now = time.time()
            recent_samples = [
                s for s in self._timing_samples
                if s.stage == stage and (now - s.timestamp) <= self.window_sec
            ]
            throughput = len(recent_samples) / self.window_sec if self.window_sec > 0 else 0.0
            
            return {
                "stage": stage,
                "total_operations": total_ops,
                "avg_duration_sec": avg_duration,
                "min_duration_sec": stats["min_duration_sec"] if stats["min_duration_sec"] != float('inf') else 0.0,
                "max_duration_sec": stats["max_duration_sec"],
                "success_rate": success_rate,
                "throughput_per_sec": throughput,
                "successful_operations": stats["successful_operations"],
                "failed_operations": stats["failed_operations"],
                "last_operation_time": stats["last_operation_time"],
            }
    
    def get_operation_metrics(self, stage: str, operation: str) -> Dict[str, Any]:
        """
        Get performance metrics for a specific operation.
        
        Args:
            stage: Stage name
            operation: Operation name
            
        Returns:
            Dictionary with operation metrics
        """
        with self._lock:
            op_key = f"{stage}.{operation}"
            op_stats = self._operation_stats.get(op_key, {})
            if not op_stats or op_stats["count"] == 0:
                return {
                    "stage": stage,
                    "operation": operation,
                    "count": 0,
                    "avg_duration_sec": 0.0,
                    "success_rate": 0.0,
                }
            
            count = op_stats["count"]
            avg_duration = op_stats["total_duration_sec"] / count if count > 0 else 0.0
            success_rate = (op_stats["success_count"] / count * 100) if count > 0 else 0.0
            
            return {
                "stage": stage,
                "operation": operation,
                "count": count,
                "avg_duration_sec": avg_duration,
                "total_duration_sec": op_stats["total_duration_sec"],
                "success_rate": success_rate,
                "success_count": op_stats["success_count"],
                "fail_count": op_stats["fail_count"],
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all performance metrics.
        
        Returns:
            Dictionary with all metrics organized by stage
        """
        with self._lock:
            stages = list(self._stage_stats.keys())
            return {
                "stages": {stage: self.get_stage_metrics(stage) for stage in stages},
                "operations": {
                    op_key: self._operation_stats[op_key].copy()
                    for op_key in self._operation_stats.keys()
                },
                "sample_count": len(self._timing_samples),
                "window_sec": self.window_sec,
            }
    
    def get_recent_timings(self, stage: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent timing samples.
        
        Args:
            stage: Optional stage filter
            limit: Maximum number of samples to return
            
        Returns:
            List of timing sample dictionaries
        """
        with self._lock:
            samples = list(self._timing_samples)
            if stage:
                samples = [s for s in samples if s.stage == stage]
            samples = samples[-limit:]  # Most recent
            return [
                {
                    "stage": s.stage,
                    "operation": s.operation,
                    "duration_sec": s.duration_sec,
                    "timestamp": s.timestamp,
                    "success": s.success,
                    "metadata": s.metadata,
                }
                for s in samples
            ]
    
    def reset(self) -> None:
        """Reset all metrics"""
        with self._lock:
            self._timing_samples.clear()
            self._stage_stats.clear()
            self._operation_stats.clear()


# Global performance monitor instance
_global_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get or create global performance monitor instance"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = PerformanceMonitor()
    return _global_monitor


def record_timing(
    stage: str,
    operation: str,
    duration_sec: float,
    success: bool = True,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Convenience function to record timing"""
    get_performance_monitor().record_timing(stage, operation, duration_sec, success, metadata)


class TimingContext:
    """Context manager for timing operations"""
    
    def __init__(
        self,
        stage: str,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.stage = stage
        self.operation = operation
        self.metadata = metadata
        self.start_time = None
        self.success = True
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.success = exc_type is None
        record_timing(
            self.stage,
            self.operation,
            duration,
            success=self.success,
            metadata=self.metadata
        )
        return False  # Don't suppress exceptions

