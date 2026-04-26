"""
Enhanced Logging System for RDNXSYS EDR

Provides structured logging with context, performance tracking, and diagnostics.
"""

import logging
import time
import functools
import traceback
from typing import Dict, Any, Optional, Callable
from contextlib import contextmanager
from collections import defaultdict, deque


class PerformanceTracker:
    """Tracks performance metrics for operations"""
    
    def __init__(self, max_samples: int = 1000):
        self.max_samples = max_samples
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self.counts: Dict[str, int] = defaultdict(int)
        self.totals: Dict[str, float] = defaultdict(float)
    
    def record(self, operation: str, duration: float):
        """Record operation duration"""
        self.metrics[operation].append(duration)
        self.counts[operation] += 1
        self.totals[operation] += duration
    
    def get_stats(self, operation: str) -> Dict[str, float]:
        """Get statistics for an operation"""
        if operation not in self.metrics or not self.metrics[operation]:
            return {"count": 0, "avg": 0.0, "min": 0.0, "max": 0.0, "total": 0.0}
        
        durations = list(self.metrics[operation])
        return {
            "count": self.counts[operation],
            "avg": sum(durations) / len(durations),
            "min": min(durations),
            "max": max(durations),
            "total": self.totals[operation]
        }
    
    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all operations"""
        return {op: self.get_stats(op) for op in self.metrics.keys()}


# Global performance tracker
_performance_tracker = PerformanceTracker()


def get_performance_tracker() -> PerformanceTracker:
    """Get the global performance tracker"""
    return _performance_tracker


@contextmanager
def timed_operation(operation_name: str, logger: Optional[logging.Logger] = None, log_level: int = logging.DEBUG):
    """
    Context manager for timing operations.
    
    Usage:
        with timed_operation("feature_extraction", logger):
            # ... do work ...
    """
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        _performance_tracker.record(operation_name, duration)
        if logger:
            logger.log(log_level, f"{operation_name} took {duration*1000:.2f}ms")


def log_execution_time(operation_name: Optional[str] = None, logger: Optional[logging.Logger] = None):
    """
    Decorator to log execution time of a function.
    
    Usage:
        @log_execution_time("process_event")
        def process_event(...):
            ...
    """
    def decorator(func: Callable):
        name = operation_name or func.__name__
        log = logger or logging.getLogger(func.__module__)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with timed_operation(name, log):
                return func(*args, **kwargs)
        return wrapper
    return decorator


class StructuredLogger:
    """
    Enhanced logger with structured context and diagnostics.
    """
    
    def __init__(self, name: str, base_logger: Optional[logging.Logger] = None):
        self.name = name
        self.logger = base_logger or logging.getLogger(name)
        self.context: Dict[str, Any] = {}
    
    def set_context(self, **kwargs):
        """Set context that will be included in all log messages"""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear context"""
        self.context.clear()
    
    def _format_message(self, message: str, **kwargs) -> str:
        """Format message with context"""
        if self.context or kwargs:
            context_str = ", ".join(f"{k}={v}" for k, v in {**self.context, **kwargs}.items())
            return f"{message} [{context_str}]"
        return message
    
    def debug(self, message: str, **kwargs):
        self.logger.debug(self._format_message(message, **kwargs))
    
    def info(self, message: str, **kwargs):
        self.logger.info(self._format_message(message, **kwargs))
    
    def warning(self, message: str, **kwargs):
        self.logger.warning(self._format_message(message, **kwargs))
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        msg = self._format_message(message, **kwargs)
        self.logger.error(msg, exc_info=exc_info)
    
    def critical(self, message: str, exc_info: bool = False, **kwargs):
        msg = self._format_message(message, **kwargs)
        self.logger.critical(msg, exc_info=exc_info)
    
    def exception(self, message: str, **kwargs):
        """Log exception with full traceback"""
        msg = self._format_message(message, **kwargs)
        self.logger.error(msg, exc_info=True)


def setup_edr_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None
) -> None:
    """
    Set up logging for the EDR system.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
        format_string: Optional custom format string
    """
    if format_string is None:
        format_string = "%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s"
    
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=format_string,
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True  # Override any existing configuration
    )
    
    # Suppress noisy loggers
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

