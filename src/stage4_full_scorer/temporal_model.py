"""
Temporal Behavior Model for Stage 4

Analyzes long-window temporal patterns, baseline learning, and time series
anomalies to detect ransomware behavior over extended time periods.
"""

import logging
import time
import math
from collections import deque, defaultdict
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("stage4_temporal_model")


@dataclass
class TemporalBaseline:
    """Baseline behavior for a process name"""
    process_name: str
    sample_count: int = 0
    
    # CPU/RAM baselines
    avg_cpu: float = 0.0
    avg_ram: float = 0.0
    cpu_std: float = 0.0
    ram_std: float = 0.0
    
    # I/O baselines
    avg_files_per_minute: float = 0.0
    avg_bytes_per_minute: float = 0.0
    avg_entropy: float = 0.0
    entropy_std: float = 0.0
    
    # Network baselines
    avg_connections_per_minute: float = 0.0
    
    # Temporal patterns
    typical_duration: float = 0.0  # Average process lifetime
    typical_peak_time: Optional[int] = None  # Hour of day when most active


@dataclass
class TemporalMetrics:
    """Temporal analysis metrics for a process"""
    baseline_deviation_score: float = 0.0
    entropy_trend: float = 0.0
    io_trend: float = 0.0
    burst_detection_score: float = 0.0
    time_series_anomaly: float = 0.0
    long_window_entropy_avg: float = 0.0
    long_window_entropy_std: float = 0.0
    io_acceleration: float = 0.0
    pattern_match_score: float = 0.0


class TemporalModel:
    """
    Temporal behavior analysis for ransomware detection.
    
    Features:
    - Long-window metrics (minutes to hours)
    - Baseline learning per process name
    - Time series anomaly detection
    - Pattern recognition for ransomware behavior
    """
    
    def __init__(self, long_window_minutes: int = 60, baseline_samples: int = 50):
        """
        Initialize Temporal Model.
        
        Args:
            long_window_minutes: Time window for long-term analysis (default 60 minutes)
            baseline_samples: Minimum samples needed for baseline (default 50)
        """
        self.long_window_minutes = long_window_minutes
        self.baseline_samples = baseline_samples
        
        # Per-PID temporal data
        self.process_data: Dict[int, Dict[str, deque]] = defaultdict(lambda: {
            'entropy': deque(maxlen=long_window_minutes),
            'io_bytes': deque(maxlen=long_window_minutes),
            'files': deque(maxlen=long_window_minutes),
            'timestamps': deque(maxlen=long_window_minutes),
            'cpu': deque(maxlen=long_window_minutes),
            'ram': deque(maxlen=long_window_minutes)
        })
        
        # Baselines per process name
        self.baselines: Dict[str, TemporalBaseline] = {}
        
        logger.info(f"TemporalModel initialized (window={long_window_minutes}min)")
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to temporal tracking"""
        try:
            pid = None
            for k in ("ProcessID", "ProcessId", "process_id", "pid"):
                if k in event:
                    try:
                        pid = int(event[k])
                        break
                    except (ValueError, TypeError):
                        continue
            
            if not pid:
                return
            
            data = self.process_data[pid]
            now = time.time()
            
            # Track entropy
            entropy = event.get("entropy") or event.get("file_entropy")
            if entropy is not None:
                try:
                    data['entropy'].append(float(entropy))
                    data['timestamps'].append(now)
                except (ValueError, TypeError):
                    pass
            
            # Track I/O
            bytes_written = event.get("bytes_written") or event.get("BytesWritten")
            if bytes_written:
                try:
                    data['io_bytes'].append(int(bytes_written))
                except (ValueError, TypeError):
                    pass
            
            # Track file operations
            if event.get("TargetFilename") or event.get("target_filename"):
                data['files'].append(now)
            
            # Update baseline for this process name
            image_path = event.get("Image") or event.get("image") or ""
            if image_path:
                process_name = self._extract_process_name(image_path)
                self._update_baseline(process_name, event)
            
        except Exception:
            logger.exception(f"Error adding event to temporal model: {event.get('EventID', 'unknown')}")
    
    def analyze_process(self, pid: int, image_path: str = "") -> TemporalMetrics:
        """
        Analyze temporal behavior for a process.
        
        Args:
            pid: Process ID
            image_path: Process image path (for baseline lookup)
            
        Returns:
            TemporalMetrics with analysis results
        """
        metrics = TemporalMetrics()
        
        if pid not in self.process_data:
            return metrics
        
        data = self.process_data[pid]
        
        # Long-window entropy analysis
        if data['entropy']:
            entropy_list = list(data['entropy'])
            metrics.long_window_entropy_avg = sum(entropy_list) / len(entropy_list)
            if len(entropy_list) > 1:
                variance = sum((x - metrics.long_window_entropy_avg) ** 2 for x in entropy_list) / len(entropy_list)
                metrics.long_window_entropy_std = math.sqrt(variance)
            
            # Entropy trend (increasing = suspicious)
            if len(entropy_list) >= 10:
                first_half = entropy_list[:len(entropy_list)//2]
                second_half = entropy_list[len(entropy_list)//2:]
                metrics.entropy_trend = (sum(second_half) / len(second_half)) - (sum(first_half) / len(first_half))
        
        # I/O trend analysis
        if data['io_bytes']:
            io_list = list(data['io_bytes'])
            metrics.io_trend = sum(io_list[-10:]) / max(1, sum(io_list[:10])) if len(io_list) >= 10 else 0.0
            
            # I/O acceleration (rate of change)
            if len(io_list) >= 5:
                recent_avg = sum(io_list[-5:]) / 5
                earlier_avg = sum(io_list[:5]) / 5 if len(io_list) >= 10 else recent_avg
                metrics.io_acceleration = (recent_avg - earlier_avg) / max(1, earlier_avg)
        
        # Burst detection
        if data['files']:
            file_times = list(data['files'])
            if len(file_times) >= 2:
                # Count files in recent window (last 10 seconds)
                now = time.time()
                recent_files = sum(1 for t in file_times if (now - t) <= 10.0)
                metrics.burst_detection_score = min(10.0, recent_files / 5.0)  # Normalize
        
        # Baseline deviation
        if image_path:
            process_name = self._extract_process_name(image_path)
            if process_name in self.baselines:
                baseline = self.baselines[process_name]
                metrics.baseline_deviation_score = self._calculate_baseline_deviation(
                    data, baseline
                )
        
        # Time series anomaly detection
        metrics.time_series_anomaly = self._detect_time_series_anomaly(data)
        
        # Pattern matching (ransomware-specific patterns)
        metrics.pattern_match_score = self._match_ransomware_patterns(data)
        
        return metrics
    
    def _extract_process_name(self, image_path: str) -> str:
        """Extract process name from full path"""
        if not image_path:
            return "unknown"
        # Get filename without extension
        import os
        name = os.path.basename(image_path)
        return name.lower().replace('.exe', '').replace('.dll', '')
    
    def _update_baseline(self, process_name: str, event: Dict[str, Any]) -> None:
        """Update baseline statistics for a process name"""
        if process_name not in self.baselines:
            self.baselines[process_name] = TemporalBaseline(process_name=process_name)
        
        baseline = self.baselines[process_name]
        baseline.sample_count += 1
        
        # Update running averages (exponential moving average)
        alpha = 0.1  # Learning rate
        
        # CPU/RAM (if available)
        cpu = event.get("cpu_usage")
        if cpu is not None:
            baseline.avg_cpu = (1 - alpha) * baseline.avg_cpu + alpha * float(cpu)
        
        ram = event.get("ram_usage")
        if ram is not None:
            baseline.avg_ram = (1 - alpha) * baseline.avg_ram + alpha * float(ram)
        
        # Entropy
        entropy = event.get("entropy") or event.get("file_entropy")
        if entropy is not None:
            baseline.avg_entropy = (1 - alpha) * baseline.avg_entropy + alpha * float(entropy)
    
    def _calculate_baseline_deviation(self, data: Dict[str, deque], baseline: TemporalBaseline) -> float:
        """Calculate how much current behavior deviates from baseline"""
        if baseline.sample_count < self.baseline_samples:
            return 0.0  # Not enough data for baseline
        
        deviation = 0.0
        
        # Entropy deviation
        if data['entropy'] and baseline.avg_entropy > 0:
            current_entropy = sum(data['entropy']) / len(data['entropy'])
            entropy_dev = abs(current_entropy - baseline.avg_entropy)
            if baseline.entropy_std > 0:
                entropy_z_score = entropy_dev / baseline.entropy_std
                deviation += min(5.0, entropy_z_score)  # Cap at 5 standard deviations
        
        # I/O deviation
        if data['io_bytes']:
            current_io = sum(data['io_bytes']) / max(1, len(data['io_bytes']))
            if baseline.avg_bytes_per_minute > 0:
                io_dev = abs(current_io - baseline.avg_bytes_per_minute) / baseline.avg_bytes_per_minute
                deviation += min(3.0, io_dev)
        
        return min(10.0, deviation)  # Cap at 10.0
    
    def _detect_time_series_anomaly(self, data: Dict[str, deque]) -> float:
        """
        Detect anomalies in time series data.
        Uses simple statistical methods (can be enhanced with LSTM/Transformer).
        """
        if not data['entropy'] or len(data['entropy']) < 10:
            return 0.0
        
        entropy_list = list(data['entropy'])
        mean = sum(entropy_list) / len(entropy_list)
        variance = sum((x - mean) ** 2 for x in entropy_list) / len(entropy_list)
        std = math.sqrt(variance) if variance > 0 else 0.0
        
        if std == 0:
            return 0.0
        
        # Count outliers (beyond 2 standard deviations)
        outliers = sum(1 for x in entropy_list if abs(x - mean) > 2 * std)
        anomaly_score = (outliers / len(entropy_list)) * 10.0
        
        return min(10.0, anomaly_score)
    
    def _match_ransomware_patterns(self, data: Dict[str, deque]) -> float:
        """
        Match temporal patterns specific to ransomware behavior.
        
        Patterns:
        - Rapid entropy increase
        - Burst of file operations
        - Sustained high I/O
        """
        score = 0.0
        
        # Pattern 1: Rapid entropy increase
        if data['entropy'] and len(data['entropy']) >= 20:
            entropy_list = list(data['entropy'])
            first_quarter = entropy_list[:len(entropy_list)//4]
            last_quarter = entropy_list[-len(entropy_list)//4:]
            
            first_avg = sum(first_quarter) / len(first_quarter)
            last_avg = sum(last_quarter) / len(last_quarter)
            
            if last_avg > first_avg + 1.0:  # Significant increase
                score += 3.0
        
        # Pattern 2: Burst of file operations
        if data['files'] and len(data['files']) >= 10:
            file_times = list(data['files'])
            # Check for burst in last 30 seconds
            now = time.time()
            recent_burst = sum(1 for t in file_times if (now - t) <= 30.0)
            if recent_burst > 20:  # More than 20 files in 30 seconds
                score += 2.5
        
        # Pattern 3: Sustained high I/O
        if data['io_bytes'] and len(data['io_bytes']) >= 10:
            io_list = list(data['io_bytes'])
            high_io_count = sum(1 for x in io_list if x > 1000000)  # > 1MB per sample
            if high_io_count > len(io_list) * 0.7:  # 70% of samples are high I/O
                score += 2.0
        
        return min(10.0, score)
    
    def cleanup_old_data(self) -> None:
        """Clean up old process data"""
        now = time.time()
        window_sec = self.long_window_minutes * 60
        
        to_remove = []
        for pid, data in self.process_data.items():
            if data['timestamps']:
                oldest = min(data['timestamps'])
                if (now - oldest) > window_sec * 2:  # 2x window
                    to_remove.append(pid)
        
        for pid in to_remove:
            del self.process_data[pid]
        
        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} old processes from temporal model")

