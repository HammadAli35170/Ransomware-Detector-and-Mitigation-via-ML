"""
Enhanced Error Handling for RDNXSYS EDR

Provides decorators and utilities for graceful error handling across all stages.
"""

import logging
import functools
from typing import Callable, Optional, Any, TypeVar, Union
from contextlib import contextmanager

logger = logging.getLogger("error_handler")

T = TypeVar('T')


def handle_errors(
    default_return: Any = None,
    log_level: int = logging.ERROR,
    reraise: bool = False,
    operation_name: Optional[str] = None
):
    """
    Decorator for graceful error handling.
    
    Args:
        default_return: Value to return on error (if reraise=False)
        log_level: Logging level for errors
        reraise: If True, re-raise exception after logging
        operation_name: Optional name for logging (defaults to function name)
    
    Usage:
        @handle_errors(default_return=None, log_level=logging.WARNING)
        def risky_operation():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        name = operation_name or func.__name__
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.log(
                    log_level,
                    f"Error in {name}: {type(e).__name__}: {e}",
                    exc_info=log_level >= logging.ERROR
                )
                if reraise:
                    raise
                return default_return
        return wrapper
    return decorator


@contextmanager
def error_context(operation_name: str, default_return: Any = None, log_level: int = logging.ERROR):
    """
    Context manager for error handling.
    
    Usage:
        with error_context("process_event", default_return=False):
            # ... risky code ...
            result = do_something()
    """
    try:
        yield
    except Exception as e:
        logger.log(
            log_level,
            f"Error in {operation_name}: {type(e).__name__}: {e}",
            exc_info=log_level >= logging.ERROR
        )
        return default_return


def safe_execute(func: Callable[..., T], *args, default: Any = None, **kwargs) -> Union[T, Any]:
    """
    Safely execute a function with error handling.
    
    Usage:
        result = safe_execute(risky_function, arg1, arg2, default="fallback")
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.debug(f"Error executing {func.__name__}: {e}", exc_info=True)
        return default


class ResilientProcessor:
    """
    Process events with automatic error recovery and statistics.
    """
    
    def __init__(self, processor_name: str):
        self.name = processor_name
        self.processed_count = 0
        self.error_count = 0
        self.last_error: Optional[Exception] = None
    
    def process(self, func: Callable, *args, **kwargs) -> tuple[bool, Any]:
        """
        Process with error handling. Returns (success, result).
        """
        try:
            result = func(*args, **kwargs)
            self.processed_count += 1
            return True, result
        except Exception as e:
            self.error_count += 1
            self.last_error = e
            logger.warning(
                f"{self.name}: Processing error ({self.error_count} total): {e}",
                exc_info=False
            )
            return False, None
    
    def get_stats(self) -> dict:
        """Get processing statistics"""
        total = self.processed_count + self.error_count
        success_rate = (self.processed_count / total * 100) if total > 0 else 0.0
        return {
            "name": self.name,
            "processed": self.processed_count,
            "errors": self.error_count,
            "success_rate_pct": round(success_rate, 2),
            "last_error": str(self.last_error) if self.last_error else None
        }

